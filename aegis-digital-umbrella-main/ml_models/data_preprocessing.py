import pandas as pd
import json
from sklearn.model_selection import train_test_split
from transformers import AutoTokenizer

# Load training data
try:
    train_df = pd.read_csv("/home/ubuntu/Aegis-Digital-Umbrella-Cybersecurity-Chatbot/Aegis-Digital-Umbrella/dataset_training.csv")
    # For simplicity, let\'s assume all questions in this dataset are cybersecurity-related
    train_df["label"] = 1  # 1 for cybersecurity
except FileNotFoundError:
    print("Training data file not found. Please ensure dataset_training.csv exists.")
    exit()

# Load validation data
try:
    with open("/home/ubuntu/Aegis-Digital-Umbrella-Cybersecurity-Chatbot/Aegis-Digital-Umbrella/dataset_validation.json", "r") as f:
        val_data = json.load(f)
    val_questions = [item["question"] for item in val_data]
    # For simplicity, let\'s assume all questions in this dataset are cybersecurity-related
    val_labels = [1] * len(val_questions)
    val_df = pd.DataFrame({"Question": val_questions, "label": val_labels})
except FileNotFoundError:
    print("Validation data file not found. Please ensure dataset_validation.json exists.")
    exit()

# Initialize tokenizer (using a common pre-trained model for demonstration)
tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")

def tokenize_function(texts):
    return tokenizer(texts.tolist(), padding="max_length", truncation=True, return_tensors="tf")

# Tokenize datasets
train_encodings = tokenize_function(train_df["Question"])
val_encodings = tokenize_function(val_df["Question"])

# Save processed data (example - in a more complex pipeline, this might be TFRecord files)
import tensorflow as tf

def create_tf_dataset(encodings, labels):
    dataset = tf.data.Dataset.from_tensor_slices((
        {"input_ids": encodings["input_ids"], "attention_mask": encodings["attention_mask"]},
        tf.constant(labels, dtype=tf.int32)
    ))
    return dataset

train_dataset = create_tf_dataset(train_encodings, train_df["label"].values)
val_dataset = create_tf_dataset(val_encodings, val_df["label"].values)

# Save datasets for later use
tf.data.experimental.save(train_dataset, "/home/ubuntu/Aegis-Digital-Umbrella-Cybersecurity-Chatbot/Aegis-Digital-Umbrella/train_tf_dataset")
tf.data.experimental.save(val_dataset, "/home/ubuntu/Aegis-Digital-Umbrella-Cybersecurity-Chatbot/Aegis-Digital-Umbrella/val_tf_dataset")

print("Data preprocessing complete and TensorFlow datasets saved.")

