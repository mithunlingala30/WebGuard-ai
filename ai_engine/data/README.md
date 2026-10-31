# AI engine data

This folder is intentionally empty of datasets.

WebGuard AI classifies severity with **transparent rules** (`classifier.py`). To add the optional
machine-learning advisor, place an analyst-labelled `labeled_findings.csv` here and run
`python -m ai_engine.train_model` - see the docstring in `train_model.py` for the format.
A model trained on fabricated data would be meaningless, so none is provided.
