"""Extract LSTM semantic features for the SCG + VAE fused dataset."""

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import load_model


LSTM_DIR = Path(__file__).resolve().parent
LG_ROOT = LSTM_DIR.parents[2]
if str(LG_ROOT) not in sys.path:
    sys.path.insert(0, str(LG_ROOT))

from tools import get_lstm_dataset_with_generated  # noqa: E402


def _feature_frame(features, labels):
    data = pd.DataFrame(features)
    data.insert(0, "label", labels.astype("int64"))
    return data


def extract_lstm_features(
    vul_type,
    generated_num,
    model_path,
    layer_name,
    max_len,
    batch_size,
    random_state,
):
    X_train, X_val, X_test, y_train, y_val, y_test = get_lstm_dataset_with_generated(
        vul_type=vul_type,
        generated_num=generated_num,
        max_len=max_len,
        random_state=random_state,
    )

    model = load_model(model_path, compile=False)
    feature_model = tf.keras.Model(inputs=model.input, outputs=model.get_layer(layer_name).output)

    train_features = feature_model.predict(X_train, batch_size=batch_size, verbose=1)
    val_features = feature_model.predict(X_val, batch_size=batch_size, verbose=1)
    test_features = feature_model.predict(X_test, batch_size=batch_size, verbose=1)

    output_dir = LSTM_DIR / "outputs" / "features"
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"features_scg_{vul_type}_gen{generated_num}_{layer_name}"

    train_file = output_dir / f"{stem}_train.csv"
    val_file = output_dir / f"{stem}_val.csv"
    test_file = output_dir / f"{stem}_test.csv"

    _feature_frame(train_features, y_train).to_csv(train_file, index=False)
    _feature_frame(val_features, y_val).to_csv(val_file, index=False)
    _feature_frame(test_features, y_test).to_csv(test_file, index=False)

    print("Saved feature files:")
    print(" ", train_file)
    print(" ", val_file)
    print(" ", test_file)
    print("Feature shapes:")
    print("  train:", train_features.shape)
    print("  val:  ", val_features.shape)
    print("  test: ", test_features.shape)

    return train_file, val_file, test_file


def parse_args():
    parser = argparse.ArgumentParser(description="Extract LSTM semantic features from a trained SCG-LSTM model.")
    parser.add_argument("--vul-type", default="reentrancy")
    parser.add_argument("--generated-num", type=int, default=3000)
    parser.add_argument("--model-path", default=None)
    parser.add_argument("--layer-name", default="LSTM")
    parser.add_argument("--max-len", type=int, default=500)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--random-state", type=int, default=1)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    model_path = args.model_path
    if model_path is None:
        model_path = LSTM_DIR / "outputs" / f"lstm_scg_{args.vul_type}_gen{args.generated_num}.h5"
    extract_lstm_features(
        vul_type=args.vul_type,
        generated_num=args.generated_num,
        model_path=model_path,
        layer_name=args.layer_name,
        max_len=args.max_len,
        batch_size=args.batch_size,
        random_state=args.random_state,
    )
