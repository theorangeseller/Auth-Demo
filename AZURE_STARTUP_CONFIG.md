# Azure Web App Startup Configuration

## Problem
Azure Web Apps are not automatically installing Python dependencies from `requirements.txt`, causing the `ModuleNotFoundError: No module named 'jwt'` error.

## Solution
Configure Azure to use a custom startup command that installs dependencies before starting the application.

## Option 1: Use Python Startup Script (Recommended)
Set the startup command in Azure Portal:

```
python startup.py && gunicorn main:app --bind=0.0.0.0:8000 --timeout 600
```

## Option 2: Use Bash Startup Script
Set the startup command in Azure Portal:

```
bash startup.sh
```

## Option 3: Direct Gunicorn with Dependency Install
Set the startup command in Azure Portal:

```
pip install -r requirements.txt && gunicorn main:app --bind=0.0.0.0:8000 --timeout 600
```

## How to Configure in Azure Portal

1. Go to your Azure Web App in the Azure Portal
2. Navigate to **Configuration** → **General settings**
3. In the **Startup Command** field, enter one of the commands above
4. Click **Save**
5. Restart your web app

## Alternative: Use Azure CLI

```bash
az webapp config set --resource-group <your-resource-group> --name <your-app-name> --startup-file "python startup.py && gunicorn main:app --bind=0.0.0.0:8000 --timeout 600"
```

## Verification

After configuration, check the Azure Web App logs to see:
- Dependencies being installed
- JWT package verification
- Successful application startup

## Why This is Needed

Azure's automatic Python app detection and Oryx build system is not reliably installing dependencies in this case. The custom startup command ensures:

1. Dependencies are installed from `requirements.txt`
2. Critical packages like `pyjwt` are verified
3. Proper error handling and fallback installation
4. The application starts only after dependencies are ready 