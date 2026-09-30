"""
Feature 12 - reusable recursive (free-running) K-step rollout logic for the
frozen Feature 10 LSTM World Model.

Mathematical formulation:

    Fθ(S(t-9), ..., S(t)) = Ŝ(t+1)

Recursively:

    Ŝ(t+2) = Fθ(S(t-8), ..., S(t), Ŝ(t+1))
    Ŝ(t+3) = Fθ(S(t-7), ..., S(t), Ŝ(t+1), Ŝ(t+2))
    ...

At every step the model always receives exactly `sequence_length` (10)
timesteps: drop the oldest, append the most recent prediction.

"After the first prediction, each subsequent forecast step uses the
model's own previous prediction rather than the ground-truth future
state." This is a free-running rollout, NOT teacher forcing: the actual
future state is never substituted back into the input history.

This module contains no training code and never calls .fit()/.backward()/
optimizer.step() - the model is used strictly in eval()/no_grad() mode.
"""

import torch


@torch.no_grad()
def recursive_rollout(model, initial_history: torch.Tensor, k_max: int) -> torch.Tensor:
    """
    Args:
        model: a frozen (eval-mode) LSTMWorldModel.
        initial_history: (batch, sequence_length, feature_dim) tensor - S(t-9..t).
        k_max: number of recursive steps to roll out.

    Returns:
        (batch, k_max, feature_dim) tensor of Ŝ(t+1) .. Ŝ(t+k_max), in order.
        predictions[:, h-1, :] is the horizon-h forecast.
    """
    assert not model.training, "recursive_rollout requires the model in eval() mode."
    history = initial_history.clone()
    predictions = []
    for _ in range(k_max):
        pred = model(history)  # (batch, feature_dim) - one free-running step
        predictions.append(pred)
        history = torch.cat([history[:, 1:, :], pred.unsqueeze(1)], dim=1)
    return torch.stack(predictions, dim=1)  # (batch, k_max, feature_dim)


@torch.no_grad()
def batched_recursive_rollout(model, X: torch.Tensor, k_max: int, device, batch_size: int = 512) -> torch.Tensor:
    """Batched wrapper around recursive_rollout for large input arrays."""
    model.eval()
    outputs = []
    for i in range(0, X.shape[0], batch_size):
        xb = X[i:i + batch_size].to(device)
        outputs.append(recursive_rollout(model, xb, k_max).cpu())
    return torch.cat(outputs, dim=0)
