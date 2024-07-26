import sys
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import confusion_matrix, classification_report, roc_curve, auc
from sklearn.model_selection import cross_val_score
from xgboost import XGBClassifier
import matplotlib.pyplot as plt
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.smbclient import SMB2_Header, SMB_Header

def label_packet(packet):
    # Detects privileged access, data access, exploitation, credential harvesting, botnet recruitment, and reconnaissance in HTTP Requests against a Web Server.
    if HTTPRequest in packet:
        if packet.haslayer(HTTPRequest):
            if packet[HTTPRequest].Path.startswith(b'/admin'):
                return 1  # Malicious
    # Detects potential network scanning activity by identifying FIN, Push, and Urgent TCP flags, botnet activity, and DNS tunneling in TCP and UDP packets.
    elif TCP in packet:
        flags = packet[TCP].flags
        if flags & 0x01 != 0 or flags & 0x08 != 0 or flags & 0x20 != 0:
            return 1  # Malicious (FIN, PSH, URG flags set)
        # Check for common botnet indicators by identifying SYN and FIN flags in TCP packets. IRC port 6667 is often used by botnets.
        if flags & (0x02 | 0x01) != 0 or packet[TCP].dport == 6667:
            return 1  # Malicious (potential botnet activity)
    elif SMB2_Header in packet:
        if packet.haslayer(SMB2_Header):
            if packet[SMB2_Header].Command == 12:  # SMB_COM_SESSION_SETUP_ANDX (command for session setup)
                return 1  # Malicious (potential lateral movement)
            if packet[SMB2_Header].Command == 37:  # SMB_COM_TREE_CONNECT (command for tree connect)
                if b'Users\\' in packet[SMB2_Header].Path.decode('utf-16le', errors='ignore'):
                    return 1  # Malicious (attempt to access Users directory)
    elif SMB_Header in packet:
        if packet.haslayer(SMB_Header):
            if packet[SMB_Header].Command == 12:  # SMB_COM_SESSION_SETUP_ANDX (command for session setup)
                return 1  # Malicious (potential lateral movement)
            if packet[SMB_Header].Command == 37:  # SMB_COM_TREE_CONNECT (command for tree connect)
                if b'Users\\' in packet[SMB_Header].Path.decode('utf-16le', errors='ignore'):
                    return 1  # Malicious (attempt to access Users directory)
    return 0  # Benign

def process_pcap(file_name):
    data = []
    packets = rdpcap(file_name)
    print(f'Opening PCAP: {file_name}')
    for packet in packets:
        packet_data = []

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            total_length = packet[IP].len
            ttl = packet[IP].ttl
            protocol = packet[IP].proto
        else:
            src_ip = np.nan
            dst_ip = np.nan
            total_length = np.nan
            ttl = np.nan
            protocol = np.nan

        packet_data.extend([src_ip, dst_ip, total_length, ttl, protocol])

        if IP in packet:
            more_fragments = packet[IP].flags.MF if 'MF' in packet[IP].flags else 0
            dont_fragment = packet[IP].flags.DF if 'DF' in packet[IP].flags else 0
            fragment_offset = packet[IP].frag if 'frag' in packet[IP] else 0
            sequence_of_bytes = bytes(packet) if 'payload' in packet[IP] else b''
        else:
            more_fragments = 0
            dont_fragment = 0
            fragment_offset = 0
            sequence_of_bytes = b''

        packet_data.extend([more_fragments, dont_fragment, fragment_offset, sequence_of_bytes])

        if TCP in packet:
            window_size = packet[TCP].window
            ack = packet[TCP].ack
            seq_num = packet[TCP].seq
            tcp_len = packet[TCP].dataofs
            urgent_pointer = packet[TCP].urgptr
            tcp_flags = packet[TCP].flags
        else:
            window_size = np.nan
            ack = np.nan
            seq_num = np.nan
            tcp_len = np.nan
            urgent_pointer = np.nan
            tcp_flags = np.nan

        packet_data.extend([window_size, ack, seq_num, tcp_len, urgent_pointer, tcp_flags])

        if UDP in packet:
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
        else:
            udp_sport = np.nan
            udp_dport = np.nan

        packet_data.extend([udp_sport, udp_dport])

        if HTTPRequest in packet:
            http_request = {
                'Method': packet[HTTPRequest].Method,
                'Host': packet[HTTPRequest].Host,
                'Path': packet[HTTPRequest].Path
            }
            http_request_payload = bytes(packet[HTTPRequest].payload)
        else:
            http_request = {}
            http_request_payload = b''

        packet_data.extend([http_request, http_request_payload])

        if HTTPResponse in packet:
            http_response = {
                'Status_Code': packet[HTTPResponse].Status_Code,
                'Reason_Phrase': packet[HTTPResponse].Reason_Phrase
            }
            http_response_payload = bytes(packet[HTTPResponse].payload)
        else:
            http_response = {}
            http_response_payload = b''

        packet_data.extend([http_response, http_response_payload])

        if SMB2_Header in packet:
            if packet.haslayer(SMB2_Header):
                smb_command = packet[SMB2_Header].Command
                smb_path = packet[SMB2_Header].fields.get('Path', b'').decode('utf-16le', errors='ignore')
                # Check for specific SMB commands or paths
                if smb_command == 12:  # SMB_COM_SESSION_SETUP_ANDX
                    packet_data.append(1)  # Mark as malicious (example)
                elif smb_command == 37:  # SMB_COM_TREE_CONNECT
                    if b'Users\\' in packet[SMB2_Header].fields.get('Path', b''):
                        packet_data.append(1)  # Mark as malicious (example)
                else:
                    packet_data.append(0)  # Benign
        elif SMB_Header in packet:
            if packet.haslayer(SMB_Header):
                smb_command = packet[SMB_Header].Command
                smb_path = packet[SMB_Header].fields.get('Path', b'').decode('utf-16le', errors='ignore')
                # Check for specific SMB commands or paths
                if smb_command == 12:  # SMB_COM_SESSION_SETUP_ANDX
                    packet_data.append(1)  # Mark as malicious (example)
                elif smb_command == 37:  # SMB_COM_TREE_CONNECT
                    if b'Users\\' in packet[SMB_Header].fields.get('Path', b''):
                        packet_data.append(1)  # Mark as malicious (example)
                else:
                    packet_data.append(0)  # Benign
        else:
            packet_data.append(0)  # No SMB header

        # Label packet using label_packet function
        label = label_packet(packet)
        packet_data.append(label)

        data.append(packet_data)

    return data

# Use the pcap file path as a command-line argument
pcap_file_path = sys.argv[1]
data = process_pcap(pcap_file_path)

# Convert data to DataFrame
df = pd.DataFrame(data, columns=["src IP", "dst IP", "IP Total Length", "TTL", "protocol",
                                 "more fragments", "dont fragment", "fragment offset",
                                 "sequence of bytes", "window size", "ack", "sequence number",
                                 "tcp length", "urgent pointer", "tcp flags", "udp sport",
                                 "udp dport", "http_request", "http_request_payload",
                                 "http_response", "http_response_payload", "smb_label", "label"])

# Split data into features (X) and target (y)
X = df.drop('label', axis=1)
y = df['label']

# Initialize LabelEncoder for SMB-related labels
smb_label_encoder = LabelEncoder()

# Fit and transform SMB labels
X['smb_label'] = smb_label_encoder.fit_transform(X['smb_label'].astype(str))

# Split data into training and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Use a single LabelEncoder instance for IP addresses
ip_encoder = LabelEncoder()

# Fit the LabelEncoder on both training and test IP addresses
combined_ips = pd.concat([X_train['src IP'], X_train['dst IP'], X_test['src IP'], X_test['dst IP']], ignore_index=True)
ip_encoder.fit(combined_ips.astype(str))  # Convert to string for LabelEncoder

# Assuming 'data' is already populated with packet data including labels
# Initialize counters
malicious_count = 0
benign_count = 0

# Iterate through data to count malicious and benign packets
for packet_data in data:
    label = packet_data[-1]
    if label == 1:
        malicious_count += 1
    elif label == 0:
        benign_count += 1

# Print totals
print(f"Total Malicious Packets: {malicious_count}")
print(f"Total Benign Packets: {benign_count}")
print(f"Total Packets: {malicious_count + benign_count}\n")

# Transform IP addresses in training set
X_train['src IP'] = ip_encoder.transform(X_train['src IP'].astype(str))
X_train['dst IP'] = ip_encoder.transform(X_train['dst IP'].astype(str))

# Transform IP addresses in test set, handling unseen labels
X_test['src IP'] = ip_encoder.transform(X_test['src IP'].astype(str))
X_test['dst IP'] = ip_encoder.transform(X_test['dst IP'].astype(str))

# Example of handling HTTP-related columns (simplified)
X_train['http_request'] = X_train['http_request'].apply(lambda x: len(str(x)))  # Convert http_request to string length

# Ensure all remaining columns are numeric
X_train = X_train.apply(pd.to_numeric, errors='coerce')  # Convert DataFrame to numeric with coercing errors
X_test = X_test.apply(pd.to_numeric, errors='coerce')

# Handle any remaining NaN values appropriately
X_train.fillna(0, inplace=True)  # Fill NaN values with 0 or other appropriate strategy
X_test.fillna(0, inplace=True)

# Define the parameter grid
param_grid = {
    'n_estimators': [100, 200, 300],
    'max_depth': [3, 5, 7],
    'learning_rate': [0.1, 0.01, 0.001]
}

# Train model
model = XGBClassifier()
model.fit(X_train, y_train)

# Predict
predictions = model.predict(X_test)

# Evaluate model performance (example)
accuracy = np.mean(predictions == y_test)
print(f"Accuracy: {accuracy}\n")

# Print Classification Report
print(f"Classification Report: \n", classification_report(y_test, predictions))

# Compute confusion matrix
cm = confusion_matrix(y_test, predictions)
print("Confusion Matrix: \n", cm)

# Get ROC curve
fpr, tpr, thresholds = roc_curve(y_test, predictions)
roc_auc = auc(fpr, tpr)

# Plot ROC curve
plt.figure()
plt.plot(fpr, tpr, color='darkorange', lw=2, label='ROC curve (area = %0.2f)' % roc_auc)
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic')
plt.legend(loc="lower right")
plt.show()

# Feature importance
feature_importances = model.feature_importances_
feature_names = X_train.columns

# Sort feature importances in descending order
sorted_idx = np.argsort(feature_importances)[::-1]

print("\nFeature Importances:")
for i in sorted_idx:
    print(f"{feature_names[i]}: {feature_importances[i]}")

# Perform cross-validation
cv_scores = cross_val_score(model, X_train, y_train, cv=5)
print(f"\nCross-validation scores: {cv_scores}")
print(f"Mean CV accuracy: {np.mean(cv_scores)}")
