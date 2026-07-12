@description('Globally unique storage account name.')
param storageAccountName string

@description('Azure region.')
param location string = resourceGroup().location

@description('Enable the controlled public-access condition. Use only for a short lab window.')
param enablePublicLab bool = false

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  tags: {
    environment: 'portfolio-lab'
    owner: 'Upenyu'
    purpose: 'cloud-security-monitoring'
  }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: enablePublicLab
    allowSharedKeyAccess: true
    publicNetworkAccess: 'Enabled'
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    deleteRetentionPolicy: {
      enabled: true
      days: 7
    }
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 7
    }
  }
}

resource labContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'public-lab'
  properties: {
    publicAccess: enablePublicLab ? 'Blob' : 'None'
  }
}

output storageResourceId string = storage.id
output containerName string = labContainer.name
output anonymousAccessEnabled bool = enablePublicLab
