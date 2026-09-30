"""
Feature 10 - LSTM-based Network World Model architecture.

Learns an approximation of:

    P(S(t+1) | S(t-9), ..., S(t))

where S(t) is the 68-dimensional network state produced by Feature 5/6/7.
Given a sequence of 10 historical network states, the model predicts the
next state vector (regression, not classification).

This module contains ONLY the architecture. Training, data loading, and
evaluation live in train_lstm_world_model.py.
"""

import torch
import torch.nn as nn


class LSTMWorldModel(nn.Module):
    """
    LSTM temporal network-state dynamics model.

    Architecture:
        (batch, seq_len, input_size)
            -> LSTM(input_size, hidden_size, num_layers, dropout)
            -> final hidden state of the last LSTM layer
            -> Linear(hidden_size, input_size)
            -> predicted next state (batch, input_size)

    Not a classifier: the output head predicts a continuous 68-dimensional
    state vector, trained with a regression loss (MSE).
    """

    def __init__(self, input_size: int = 68, hidden_size: int = 128, num_layers: int = 2, dropout: float = 0.2):
        super().__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.dropout = dropout

        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        self.output_head = nn.Linear(hidden_size, input_size)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: (batch, seq_len, input_size) - the 10-window state history.
        Returns:
            (batch, input_size) - predicted next network state S(t+1).
        """
        _, (h_n, _) = self.lstm(x)
        final_hidden = h_n[-1]  # last layer's final hidden state: (batch, hidden_size)
        predicted_next_state = self.output_head(final_hidden)
        return predicted_next_state

    def config_dict(self) -> dict:
        return {
            "input_size": self.input_size,
            "hidden_size": self.hidden_size,
            "num_layers": self.num_layers,
            "dropout": self.dropout,
        }
