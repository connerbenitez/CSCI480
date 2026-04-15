from __future__ import annotations

import math

import torch
import torch.nn as nn
import torch.nn.functional as F


class Autoencoder(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(hidden_dim, input_dim),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        encoded = self.encoder(x)
        return self.decoder(encoded)


class PPOPolicyNetwork(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int, action_dim: int):
        super().__init__()
        self.shared = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
        )
        self.policy_head = nn.Linear(hidden_dim, action_dim)
        self.value_head = nn.Linear(hidden_dim, 1)

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        features = self.shared(x)
        logits = self.policy_head(features)
        values = self.value_head(features).squeeze(-1)
        return logits, values


class SimpleGraphSAGELayer(nn.Module):
    def __init__(self, in_dim: int, out_dim: int):
        super().__init__()
        self.linear = nn.Linear(in_dim * 2, out_dim)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        num_nodes = x.size(0)
        src, dst = edge_index

        agg = torch.zeros_like(x)
        deg = torch.zeros(num_nodes, device=x.device, dtype=x.dtype)
        agg.index_add_(0, dst, x[src])
        deg.index_add_(0, dst, torch.ones_like(dst, dtype=x.dtype))
        deg = deg.clamp_min(1.0).unsqueeze(-1)
        neigh = agg / deg
        return self.linear(torch.cat([x, neigh], dim=1))


class FlowGNN(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int, output_dim: int, dropout: float = 0.2):
        super().__init__()
        self.conv1 = SimpleGraphSAGELayer(input_dim, hidden_dim)
        self.conv2 = SimpleGraphSAGELayer(hidden_dim, hidden_dim)
        self.classifier = nn.Linear(hidden_dim, output_dim)
        self.dropout = dropout

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)
        return self.classifier(x)


def knn_edge_index(features: torch.Tensor, k: int = 8) -> torch.Tensor:
    if features.size(0) == 1:
        return torch.tensor([[0], [0]], dtype=torch.long, device=features.device)

    k = max(1, min(k, features.size(0) - 1))
    distances = torch.cdist(features, features)
    knn = torch.topk(distances, k=k + 1, largest=False).indices[:, 1:]
    src = torch.arange(features.size(0), device=features.device).unsqueeze(1).expand_as(knn)
    edges = torch.stack([src.reshape(-1), knn.reshape(-1)], dim=0)

    reverse_edges = torch.stack([edges[1], edges[0]], dim=0)
    self_loops = torch.arange(features.size(0), device=features.device)
    self_loops = torch.stack([self_loops, self_loops], dim=0)
    return torch.cat([edges, reverse_edges, self_loops], dim=1)


def hidden_dim_for_features(input_dim: int, minimum: int = 16, maximum: int = 128) -> int:
    return max(minimum, min(maximum, 2 ** math.ceil(math.log2(max(2, input_dim // 2)))))
