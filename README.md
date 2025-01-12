<div align="center">
  
  <h2>ACADEMY OF CRYPTOGRAPHY TECHNIQUES</h2>
  <h3></h3>
  <h3></h3>
  <br />
  
  <img src="https://navigates.vn/wp-content/uploads/2023/06/logo-hoc-vien-ky-thuat-mat-ma.jpg" alt="logo" style="width: auto; height: auto;">
  
  <br />
  <br />

</div>

<h1 align="center">💡 Project: Integrating Machine Learning into ModSecurity for Nginx 💡</h1>

This project provides guidance on integrating TensorFlow into ModSecurity on Nginx to enhance the detection of web attacks (e.g., SQL Injection, XSS) using machine learning models. It includes steps for training and integrating a TensorFlow model to analyze and classify HTTP requests for potential threats

## Key Features

- Machine Learning Integration: Enhances ModSecurity with TensorFlow to detect malicious requests using trained models.
- Customizable Models: Allows users to train and integrate their own TensorFlow models based on specific attack patterns.
- Modular Design: Easily integrates as a dynamic library (libmodsec_tensorflow.so) into ModSecurity.
- Detailed Logging: Provides comprehensive logs for debugging and monitoring via ModSecurity audit logs.

## Getting Started

To get started with integrating TensorFlow into ModSecurity, follow these steps:

1. **Set Up the Environment**:
   - Install the required system libraries and TensorFlow C API.
   - Ensure ModSecurity is properly installed and configured with Nginx.

2. **Prepare Training Data**:
   - Collect and preprocess HTTP request logs for training.

3. **Build and Test**:
   - Compile the shared library and integrate it with ModSecurity.
   - Verify the integration with test HTTP requests.


## Requirements

**Operating System**: Ubuntu 20.04 (Linux 5.15.0-97-generic)
- NGINX
- Modsecurity
- ModSecurity v3 Nginx Connector
- Tensowflow
- Conda
- Orther Package (requirements.txt)


### **Tree**

```
./
├── README.md
├── Sample_21_Dec_2024_07_52.txt
├── build_lib
│   ├── extension.txt
│   ├── ngx_http_modsecurity_header_filter.c
│   └── tokenizer.c
├── csic2010_prepare_for_keras.py
├── datasets
│   ├── CSIC2010
│   │   ├── cbow_w2v_baocao
│   │   ├── cbow_w2v_last
│   │   ├── model1
│   │   │   ├── fingerprint.pb
│   │   │   ├── keras_metadata.pb
│   │   │   ├── saved_model.pb
│   │   │   └── variables
│   │   │       ├── variables.data-00000-of-00001
│   │   │       └── variables.index
│   │   ├── model9
│   │   │   ├── fingerprint.pb
│   │   │   ├── keras_metadata.pb
│   │   │   ├── saved_model.pb
│   │   │   └── variables
│   │   │       ├── variables.data-00000-of-00001
│   │   │       └── variables.index
│   │   ├── model_csic
│   │   │   ├── fingerprint.pb
│   │   │   ├── keras_metadata.pb
│   │   │   ├── saved_model.pb
│   │   │   └── variables
│   │   │       ├── variables.data-00000-of-00001
│   │   │       └── variables.index
│   │   ├── model_final_97
│   │   │   ├── fingerprint.pb
│   │   │   ├── keras_metadata.pb
│   │   │   ├── saved_model.pb
│   │   │   └── variables
│   │   │       ├── variables.data-00000-of-00001
│   │   │       └── variables.index
│   │   ├── model_final_97_baocao
│   │   │   ├── fingerprint.pb
│   │   │   ├── keras_metadata.pb
│   │   │   ├── saved_model.pb
│   │   │   └── variables
│   │   │       ├── variables.data-00000-of-00001
│   │   │       └── variables.index
│   │   ├── model_final_97_baocaoo
│   │   │   ├── fingerprint.pb
│   │   │   ├── keras_metadata.pb
│   │   │   ├── saved_model.pb
│   │   │   └── variables
│   │   │       ├── variables.data-00000-of-00001
│   │   │       └── variables.index
│   │   └── model_final_batchsize_32
│   │       ├── fingerprint.pb
│   │       ├── keras_metadata.pb
│   │       ├── saved_model.pb
│   │       └── variables
│   │           ├── variables.data-00000-of-00001
│   │           └── variables.index
│   ├── TongHop
│   │   ├── anor-Parsed.txt
│   │   ├── norm-Parsed.txt
│   │   └── test.txt
│   ├── baocao
│   │   ├── 80_OK_csic2010-anomalous-test-parsed.txt
│   │   ├── 80_OK_csic2010-normal-test-parsed.txt
│   │   ├── anomalous-parsed.txt
│   │   └── normal-parsed.txt
│   ├── models_keras
│   │   ├── model_cnn2d.keras
│   │   └── model_lstm_cnn2d.keras
│   └── token_baocao.txt
└── requirements.txt
```

### **Building the Library**

1. **Compile as a Shared Library**:

   Compile the `ngx_http_modsecurity_header_filter.c` file:

   ```bash
   gcc -shared -o libmodsec_tensorflow.so -fPIC \
       -I/usr/local/include \
       -L/usr/local/lib \
       ngx_http_modsecurity_header_filter.c \
       -ltensorflow
   ```

2. **Verify the Library**:
   
   ```bash
   ls -l libmodsec_tensorflow.so
   ```

---

### **Training and Integrating the TensorFlow Model**

1. **Prepare Training Data**:

   - Collect HTTP request logs (e.g., from ModSecurity) and label them as normal or malicious.
   - Preprocess the data into a format suitable for training (e.g., tokenize and vectorize the input).

2. **Train the TensorFlow Model**:
```
git clone https://github.com/datnlq/Project-machinelearning-in-Modsec_NGINX.git
cd Project-machinelearning-in-Modsec_NGINX
```

```
python3 csic2010_prepare_for_keras.py
```

4. **Integrate the Model with ModSecurity**:

   - Use the TensorFlow C API in `ngx_http_modsecurity_header_filter.c` to load the model and make predictions.

---

### **Notes**

- **Performance**: TensorFlow can be resource-intensive, especially when handling high traffic. Consider using TensorFlow Lite or GPU acceleration if needed.
- **Security**: Ensure that files like `extension.txt` and the TensorFlow model are secured to prevent unauthorized access.

---
<div align="center">
  <img src="https://skillicons.dev/icons?i=python,vscode,github,git,md,stackoverflow,tensorflow" alt="Tools and Languages" />
</div>
---

<h2 align="center">Contributors </h2>

<div align="center">
  <a href="https://github.com/datnlq"><img src="https://avatars.githubusercontent.com/u/77602549?v=4" title="pdz1804" width="50" height="50"></a>
  </div>
