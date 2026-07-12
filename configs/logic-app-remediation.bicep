@description('Logic App name.')
param logicAppName string = 'la-lock-public-blob-access'

@description('Azure region.')
param location string = resourceGroup().location

resource workflow 'Microsoft.Logic/workflows@2019-05-01' = {
  name: logicAppName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  tags: {
    environment: 'portfolio-lab'
    purpose: 'storage-auto-remediation'
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {}
      triggers: {
        receive_remediation_request: {
          type: 'Request'
          kind: 'Http'
          inputs: {
            schema: {
              type: 'object'
              required: [
                'subscriptionId'
                'resourceGroupName'
                'storageAccountName'
              ]
              properties: {
                subscriptionId: { type: 'string' }
                resourceGroupName: { type: 'string' }
                storageAccountName: { type: 'string' }
              }
            }
          }
        }
      }
      actions: {
        disable_anonymous_blob_access: {
          type: 'Http'
          inputs: {
            method: 'PATCH'
            uri: "@{concat('https://management.azure.com/subscriptions/', triggerBody()?['subscriptionId'], '/resourceGroups/', triggerBody()?['resourceGroupName'], '/providers/Microsoft.Storage/storageAccounts/', triggerBody()?['storageAccountName'], '?api-version=2023-05-01')}"
            authentication: { type: 'ManagedServiceIdentity', audience: 'https://management.azure.com/' }
            headers: { 'Content-Type': 'application/json' }
            body: { properties: { allowBlobPublicAccess: false } }
          }
          runAfter: {}
        }
        response: {
          type: 'Response'
          kind: 'Http'
          inputs: {
            statusCode: 200
            body: {
              status: 'remediation-request-completed'
              storageAccountName: "@{triggerBody()?['storageAccountName']}"
              allowBlobPublicAccess: false
            }
          }
          runAfter: { disable_anonymous_blob_access: [ 'Succeeded' ] }
        }
      }
      outputs: {}
    }
  }
}

output logicAppPrincipalId string = workflow.identity.principalId
output logicAppResourceId string = workflow.id
