#!/bin/bash
# MSAuth 1.0 POC - Azure AD Setup Script (Bash)
# This script automates the Azure AD configuration for the MSAuth 1.0 demonstration application

set -e

# Default values
APP_NAME="${1:-MSAuth10-PocApp}"
CERT_NAME="${2:-MSAuth10PocApp}"
SKIP_CERT="${3:-false}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

echo -e "${CYAN}=========================================${NC}"
echo -e "${CYAN}MSAuth 1.0 POC - Azure AD Setup Script${NC}"
echo -e "${CYAN}=========================================${NC}"
echo ""

# Check if Azure CLI is installed
echo -e "${YELLOW}[Step 1/8] Checking prerequisites...${NC}"
if ! command -v az &> /dev/null; then
    echo -e "${RED}❌ Azure CLI is not installed.${NC}"
    echo -e "${YELLOW}Please install from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli${NC}"
    exit 1
fi

AZ_VERSION=$(az --version | grep "azure-cli" | head -1)
echo -e "${GREEN}✓ Azure CLI is installed: $AZ_VERSION${NC}"

# Check if OpenSSL is installed (for certificate generation)
if [ "$SKIP_CERT" != "true" ]; then
    if ! command -v openssl &> /dev/null; then
        echo -e "${RED}❌ OpenSSL is not installed.${NC}"
        echo -e "${YELLOW}Install OpenSSL or run with SKIP_CERT=true${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ OpenSSL is installed${NC}"
fi

# Check Azure login status
echo ""
echo -e "${YELLOW}[Step 2/8] Checking Azure login status...${NC}"

# Try to get account info to check if already logged in
if az account show > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Already logged in to Azure${NC}"
else
    echo -e "${GRAY}Not currently logged in. A browser window will open for authentication.${NC}"
    if ! az login --allow-no-subscriptions > /dev/null 2>&1; then
        echo -e "${RED}❌ Failed to login to Azure${NC}"
        exit 1
    fi
    echo -e "${GREEN}✓ Successfully logged in to Azure${NC}"
fi

# Get tenant information
TENANT_ID=$(az account show --query homeTenantId -o tsv)
TENANT_NAME=$(az account show --query name -o tsv)

echo -e "${GRAY}  Tenant ID: $TENANT_ID${NC}"
echo -e "${GRAY}  Tenant Name: $TENANT_NAME${NC}"

# Create certificate if not skipped
CERT_THUMBPRINT=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$SKIP_CERT" != "true" ]; then
    echo ""
    echo -e "${YELLOW}[Step 3/8] Creating self-signed certificate...${NC}"
    
    CERT_KEY="$SCRIPT_DIR/$CERT_NAME.key"
    CERT_CSR="$SCRIPT_DIR/$CERT_NAME.csr"
    CERT_CRT="$SCRIPT_DIR/$CERT_NAME.crt"
    CERT_PFX="$SCRIPT_DIR/$CERT_NAME.pfx"
    
    # Generate private key
    openssl genrsa -out "$CERT_KEY" 2048 2>/dev/null
    
    # Generate certificate signing request
    openssl req -new -key "$CERT_KEY" -out "$CERT_CSR" -subj "/CN=$CERT_NAME" 2>/dev/null
    
    # Generate self-signed certificate (valid for 2 years)
    openssl x509 -req -days 730 -in "$CERT_CSR" -signkey "$CERT_KEY" -out "$CERT_CRT" 2>/dev/null
    
    # Create PFX file (for Windows compatibility)
    openssl pkcs12 -export -out "$CERT_PFX" -inkey "$CERT_KEY" -in "$CERT_CRT" -passout pass: 2>/dev/null
    
    # Get thumbprint (SHA1 fingerprint)
    CERT_THUMBPRINT=$(openssl x509 -in "$CERT_CRT" -noout -fingerprint -sha1 | sed 's/://g' | cut -d'=' -f2)
    
    echo -e "${GREEN}✓ Certificate created successfully${NC}"
    echo -e "${GRAY}  Thumbprint: $CERT_THUMBPRINT${NC}"
    echo -e "${GRAY}  Certificate: $CERT_CRT${NC}"
    echo -e "${GRAY}  Private Key: $CERT_KEY${NC}"
    echo -e "${GRAY}  PFX File: $CERT_PFX${NC}"
    
    # Clean up CSR
    rm -f "$CERT_CSR"
else
    echo ""
    echo -e "${YELLOW}[Step 3/8] Skipping certificate creation (SKIP_CERT=true)${NC}"
    echo -e "${YELLOW}⚠️  You will need to manually specify a certificate thumbprint${NC}"
fi

# Create app registration
echo ""
echo -e "${YELLOW}[Step 4/8] Creating app registration...${NC}"

APP_EXISTS=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv)

if [ -n "$APP_EXISTS" ]; then
    echo -e "${YELLOW}⚠️  App '$APP_NAME' already exists${NC}"
    APP_ID="$APP_EXISTS"
else
    APP_ID=$(az ad app create --display-name "$APP_NAME" --sign-in-audience "AzureADMyOrg" --query appId -o tsv)
    echo -e "${GREEN}✓ App registration created${NC}"
fi

echo -e "${GRAY}  Application (Client) ID: $APP_ID${NC}"

# Get the app object ID for further operations
APP_OBJECT_ID=$(az ad app show --id "$APP_ID" --query id -o tsv)

# Configure API permissions
echo ""
echo -e "${YELLOW}[Step 5/8] Configuring API permissions...${NC}"

# Microsoft Graph API ID
GRAPH_API_ID="00000003-0000-0000-c000-000000000000"

# User.Read.All permission ID (Application permission)
USER_READ_ALL_ID="df021288-bdef-4463-88db-98f22de89214"

# Add the permission
az ad app permission add --id "$APP_ID" --api "$GRAPH_API_ID" --api-permissions "$USER_READ_ALL_ID=Role" > /dev/null 2>&1 || true
echo -e "${GREEN}✓ Added Microsoft Graph User.Read.All permission${NC}"

# Grant admin consent
echo -e "${GRAY}  Granting admin consent...${NC}"
sleep 5  # Wait for permission to propagate

if az ad app permission grant --id "$APP_ID" --api "$GRAPH_API_ID" --scope "User.Read.All" > /dev/null 2>&1 && \
   az ad app permission admin-consent --id "$APP_ID" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Admin consent granted${NC}"
else
    echo -e "${YELLOW}⚠️  Warning: Could not grant admin consent automatically${NC}"
    echo -e "${GRAY}  You may need to grant consent manually in Azure Portal${NC}"
fi

# Upload certificate if created
if [ "$SKIP_CERT" != "true" ]; then
    echo ""
    echo -e "${YELLOW}[Step 6/8] Uploading certificate to app registration...${NC}"
    
    if az ad app credential reset --id "$APP_ID" --cert "@$CERT_CRT" --append > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Certificate uploaded successfully${NC}"
    else
        echo -e "${YELLOW}⚠️  Warning: Could not upload certificate automatically${NC}"
        echo -e "${GRAY}  You may need to upload it manually in Azure Portal${NC}"
    fi
else
    echo ""
    echo -e "${YELLOW}[Step 6/8] Skipping certificate upload${NC}"
fi

# Update appsettings.json
echo ""
echo -e "${YELLOW}[Step 7/8] Updating appsettings.json...${NC}"

APP_SETTINGS_PATH="$SCRIPT_DIR/MSAuth10PocApp/appsettings.json"

if [ -f "$APP_SETTINGS_PATH" ]; then
    # Create a temporary file with updated settings
    TMP_FILE=$(mktemp)
    
    # Use jq if available, otherwise use sed
    if command -v jq &> /dev/null; then
        jq --arg tid "$TENANT_ID" \
           --arg cid "$APP_ID" \
           --arg thumb "$CERT_THUMBPRINT" \
           '.AzureAd.TenantId = $tid | .AzureAd.ClientId = $cid | (if $thumb != "" then .AzureAd.CertificateThumbprint = $thumb else . end)' \
           "$APP_SETTINGS_PATH" > "$TMP_FILE"
        
        mv "$TMP_FILE" "$APP_SETTINGS_PATH"
        echo -e "${GREEN}✓ Configuration updated successfully${NC}"
    else
        echo -e "${YELLOW}⚠️  jq not installed - please update appsettings.json manually${NC}"
        echo -e "${GRAY}  Install jq for automatic configuration: https://stedolan.github.io/jq/${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  appsettings.json not found at: $APP_SETTINGS_PATH${NC}"
fi

# Summary
echo ""
echo -e "${YELLOW}[Step 8/8] Setup Complete!${NC}"
echo ""
echo -e "${CYAN}=========================================${NC}"
echo -e "${CYAN}Configuration Summary${NC}"
echo -e "${CYAN}=========================================${NC}"
echo -e "Tenant ID:              $TENANT_ID"
echo -e "Application Client ID:  $APP_ID"

if [ "$SKIP_CERT" != "true" ]; then
    echo -e "Certificate Thumbprint: $CERT_THUMBPRINT"
    echo -e "Certificate Files:"
    echo -e "  - Public: $CERT_CRT"
    echo -e "  - Private: $CERT_KEY"
    echo -e "  - PFX: $CERT_PFX"
fi

echo ""
echo -e "${GREEN}Next Steps:${NC}"
echo -e "${GRAY}1. Verify the configuration in Azure Portal:${NC}"
echo -e "${GRAY}   https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/$APP_ID${NC}"
echo ""
echo -e "${GRAY}2. Run the demonstration app:${NC}"
echo -e "${GRAY}   cd MSAuth10PocApp${NC}"
echo -e "${GRAY}   dotnet run${NC}"
echo ""
echo -e "${CYAN}=========================================${NC}"
