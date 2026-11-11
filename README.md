# SignalForge — Email Threat Detector

SignalForge is a local-first cybersecurity learning project for exploring spam classification and suspicious-URL analysis. It provides a web interface for analyzing messages and URLs, understanding warning signals, and learning about the models behind the results.

> **Important:** This project is an educational demonstration, not a production security product. Its results can be wrong; do not rely on them to decide whether a message or website is safe.

## Features

- **Email analyzer:** estimates spam/ham probabilities, checks embedded URLs, and highlights cues such as urgency, credential requests, and prize bait.
- **URL scanner:** analyzes individual URLs or batches of up to 50 using lexical features and a trained model. URLs are not opened or fetched.
- **Security center:** provides browser-local password-strength feedback and a phishing-resilience checklist.
- **Model lab:** presents datasets, held-out evaluation metrics, and influential URL-model features.
- **Privacy-conscious design:** message analysis uses local models; password input stays in the browser; optional scan history is stored in browser storage.

## Technology

- Python, Flask, pandas, NumPy, and scikit-learn
- HTML, CSS, and JavaScript
- TF-IDF text features for spam/ham classification
- Lexical and structural URL features with a Random Forest classifier

## Getting started

### Requirements

- Python installed and available as `python` in PowerShell
- Windows PowerShell

### Install and run

From the project directory, create and activate a virtual environment, install dependencies, and start the app:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

The repository includes trained model files, so you can run the app without retraining. Open <http://127.0.0.1:5000> in your browser.

To retrain both models before launching:

```powershell
python train_all.py
python app.py
```

To use a different port in PowerShell:

```powershell
$env:PORT = "5055"
python app.py
```

To retrain only the URL model:

```powershell
python src\train_url_model.py --sample-size 60000
python src\train_url_model.py --full
```

`--full` trains using the complete included URL dataset and may take longer. Retraining replaces model and metric files in `models/`; restart the app afterward.

## Datasets and models

Training data is included in `data/raw/`:

- `sms_spam.tsv`: labelled SMS messages used for spam-versus-ham classification. Training compares TF-IDF Multinomial Naive Bayes and Logistic Regression, then saves the model with the stronger held-out spam F1 score.
- `malicious_urls.csv`: labelled legitimate and malicious URLs used to train a Random Forest on 22 lexical and structural features. Training uses a stratified sample by default.

The reported metrics are measured on held-out data and do not guarantee real-world performance. The URL model does not use live threat feeds, DNS, page contents, redirects, TLS certificates, or domain-registration data. A hostname allowlist for established services can reduce false positives, but does not guarantee that user content or redirects are safe. HTTPS alone does not mean a site is trustworthy.

## Tests

Run the test suite from the project directory:

```powershell
.\venv\Scripts\python.exe -m unittest discover -s tests -v
```

## API

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/` | Overview |
| `GET` | `/email-analyzer` | Message analysis page |
| `GET` | `/url-scanner` | Single and batch URL scanner |
| `GET` | `/security-center` | Browser-local password checkup and safety guidance |
| `GET` | `/model-lab` | Dataset and model details |
| `POST` | `/api/analyze` | Analyze JSON such as `{ "text": "..." }` |
| `POST` | `/api/check-url` | Analyze JSON such as `{ "url": "..." }` |
| `POST` | `/api/check-urls` | Analyze JSON such as `{ "urls": ["...", "..."] }` |
| `GET` | `/api/model-stats` | Return dataset and held-out model metrics |

## Privacy and safety

Do not enter real credentials, confidential messages, or sensitive URLs, especially on a shared computer. Password-strength feedback is calculated in the browser. The URL scanner does not visit the submitted URLs.

The Flask development server is intended for local demos and coursework, not production deployment.


<img width="1897" height="906" alt="image" src="https://github.com/user-attachments/assets/c4d25af4-9c1c-4f1b-a7a5-664fd3929dab" />
<img width="1897" height="906" alt="image" src="https://github.com/user-attachments/assets/1633a77f-8556-4fa2-a769-bec6a74fafa8" />
<img width="1897" height="906" alt="image" src="https://github.com/user-attachments/assets/0d8183a3-a825-48c7-9a8a-30e4c86b4793" />
<img width="1897" height="906" alt="image" src="https://github.com/user-attachments/assets/38dff91c-3faa-40ad-9909-6587ad0400b4" />
