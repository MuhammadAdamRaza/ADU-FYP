import tensorflow as tf
from transformers import TFAutoModelForSequenceClassification, AutoTokenizer

# Load preprocessed datasets
try:
    train_dataset = tf.data.experimental.load("/home/ubuntu/Aegis-Digital-Umbrella-Cybersecurity-Chatbot/Aegis-Digital-Umbrella/train_tf_dataset")
    val_dataset = tf.data.experimental.load("/home/ubuntu/Aegis-Digital-Umbrella-Cybersecurity-Chatbot/Aegis-Digital-Umbrella/val_tf_dataset")
except Exception as e:
    print(f"Error loading datasets: {e}")
    exit()

# Define batch size and prefetch for performance
BATCH_SIZE = 16
train_dataset = train_dataset.shuffle(1000).batch(BATCH_SIZE).prefetch(tf.data.AUTOTUNE)
val_dataset = val_dataset.batch(BATCH_SIZE).prefetch(tf.data.AUTOTUNE)

# Load pre-trained model for sequence classification
# We are using 'bert-base-uncased' as an example. For better performance in cybersecurity,
# a domain-specific pre-trained model could be considered if available.
model = TFAutoModelForSequenceClassification.from_pretrained("bert-base-uncased", num_labels=1)

# Compile the model
# Using BinaryCrossentropy for binary classification (cybersecurity vs. non-cybersecurity)
model.compile(
    optimizer=tf.keras.optimizers.Adam(learning_rate=5e-5),
    loss=tf.keras.losses.BinaryCrossentropy(from_logits=True),
    metrics=[tf.keras.metrics.BinaryAccuracy()]
)

# Train the model
print("Starting model training...")
history = model.fit(
    train_dataset,
    epochs=3,  # You can adjust the number of epochs
    validation_data=val_dataset
)

print("Model training complete.")

# Save the trained model
model_save_path = "/home/ubuntu/Aegis-Digital-Umbrella-Cybersecurity-Chatbot/Aegis-Digital-Umbrella/cybersecurity_chatbot_model"
model.save_pretrained(model_save_path)

# Save the tokenizer as well, as it's needed for inference
tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
tokenizer.save_pretrained(model_save_path)

print(f"Model and tokenizer saved to {model_save_path}")


