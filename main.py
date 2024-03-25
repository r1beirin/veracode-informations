from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
import requests

# as credentials necessitam de estar em ~/.veracode/credentials seguindo a documentação https://docs.veracode.com/r/c_api_credentials3
api_base = 'https://api.veracode.com'
headers = {'User-Agent': 'Python HMAC'}

def start(choice):
    try:
        response = requests.get(api_base + '/appsec/v1/applications', auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)
    except requests.RequestException as e:
        print(e)
    
    if response.ok:
        data = response.json()

        for app in data['_embedded']['applications']:
            guid = app['guid']
            policyName = getPolicyName(guid)
            sandboxName = getSandboxName(guid)
            appName = app["profile"]["name"]
            
            for i in app['scans']:
                lastScanStatus = i['status']
            
            if choice == '1' and lastScanStatus == 'MODULE_SELECTION_REQUIRED':
                printInfos(appName, policyName, sandboxName, lastScanStatus)
            
            elif choice == '2' and (lastScanStatus == 'MODULE_SELECTION_REQUIRED' or lastScanStatus == 'INCOMPLETE'):
                printInfos(appName, policyName, sandboxName, lastScanStatus)
            
            elif choice == '3':
                printInfos(appName, policyName, sandboxName, lastScanStatus)

def printInfos(appName, policyName, sandboxName, lastScanStatus):
    print(f'''
        AppName: {appName}
        Policy: {policyName}
        Sandbox: {sandboxName}
        Last Scan Status: {lastScanStatus}
          ''')


def getSandboxName(guid):
    try:
        response = requests.get(api_base + f'/appsec/v1/applications/{guid}/sandboxes', auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)
    except requests.RequestException as e:
        print(e)

    if response.ok:
        data = response.json()

        # Aqui verifica se possui sandbox ou não
        if '_embedded' in data:
            for i in data['_embedded']['sandboxes']:
                return i['name']

def getPolicyName(guid):
    try:
        response = requests.get(api_base + f'/appsec/v1/applications/{guid}', auth=RequestsAuthPluginVeracodeHMAC(), headers=headers)
    except requests.RequestException as e:
        print(e)

    if response.ok:
        data = response.json()

        for app in data['profile']['policies']:
            return app['name']


def main():
    print('=======================================================')
    print('1 - Mostrar somente MODULE_SELECTION_REQUIRED')
    print('2 - Mostrar MODULE_SELECTION_REQUIRED e REQUEST INCOMPLETE')
    print('3 - Mostrar tudo')

    choice = input("Escolha: ")
    
    if choice == '1': start(choice)
    elif choice == '2': start(choice)
    elif choice == '3': start(choice)
    
if __name__ == '__main__':
    main()