import base64
import boto3
import os
from urllib import request
import json


def base_header():
    """Generate http request headers.
    Need to set Atlassian id and token encrpyted by KMS to env vals.
        - ENCRYPTED_ATLASSIAN_ID: Atlassian id encrypted by KMS
        - ENCRYPTED_ATLASSIAN_TOKEN: Atlassian token encrypted by KMS

    Returns:
        dict: http header dict.

    Example:
        >>> base_header()
        {'Authorization': 'Basic xxxxxxxxxxxxxxx',
         'Content-Type': 'application/json'}
    """
    user = kms_decrypt(os.environ['ENCRYPTED_ATLASSIAN_ID'])
    token = kms_decrypt(os.environ['ENCRYPTED_ATLASSIAN_TOKEN'])
    auth = base64.b64encode(f'{user}:{token}'.encode('utf-8')).decode('utf-8')
    return {'Authorization': f'Basic {auth}',
            'Content-Type': 'application/json'}


def api_url(endpoint):
    """Generate api url.
    Need to set HOST to env val.

    Returns:
        str: api url

    Example:
        >>> api_url('content')
        'https://example.com/wiki/rest/api/content'
    """
    return f'https://{os.environ["HOST"]}/wiki/rest/api/{endpoint}'


def confluence_pages():
    """Get confluence contents.

    Returns:
        json: confluence pages data.
    """
    url = api_url('content')
    headers = base_header()
    return request_json(url=url, method='GET', headers=headers)


def create_new_page(title='new_page', space_key='3IDEA',
                    content='<p>This is a new page</p>'):
    """Create new page.
    Args:
        title (str): page title.
        space_key (str): space key.
        content (str): content html.

    Returns:
    　　json: created page.
    """
    headers = {**base_header(), **{"Content-Type": "application/json"}}
    url = api_url('content')
    json_data = {
        'type': 'page',
        'title': title,
        'space': {'key': space_key},
        'body': {'storage': {'value': content,
                             'representation': 'storage'}}}
    return request_json(url=url, method='POST',
                        headers=headers, json_data=json_data)


def page_version(page_id=834109441):
    """Get page version.
    Args:
        page_id (int): confluencd page id.

    Returns:
        int: page version.

    Example:
        >>> page_version(1000000)
        1
    """
    url = api_url(f'content/{page_id}')
    headers = base_header()
    return request_json(url=url, method='GET',
                        headers=headers)['version']['number']


def update_page(page_id=834109441, title='title',
                content='<p>This is a new page</p>'):
    """Update page.
    Args:
        page_id (int): confluence page id.
        title (str): page title.
        content (str): content html

    Returns:
        json: updated page.
    """
    headers = {**base_header(), **{"Content-Type": "application/json"}}
    url = api_url(f'content/{page_id}')
    current_version = page_version(page_id)
    json_data = {
        "version": {"number": current_version + 1},
        'type': 'page',
        'title': title,
        'body': {'storage': {'value': content,
                             'representation': 'storage'}}
    }
    return request_json(url=url, method='PUT',
                        headers=headers, json_data=json_data)


def request_json(url, method, headers, json_data=None):
    encoded_json = json.dumps(json_data).encode('utf-8')
    req = request.Request(url, method=method,
                          headers=headers, data=encoded_json)
    with request.urlopen(req) as res:
        data = json.loads(res.read())
    return data


def kms_decrypt(encrypted_txt):
    """Decypt by KMS.
    Args:
        encrypted_txt (str): text encrpyted by KMS.

    Returns:
        str: decrypted txt.
    """
    ciphertext_blob = base64.b64decode(encrypted_txt)
    kms = boto3.client('kms')
    dec = kms.decrypt(CiphertextBlob=ciphertext_blob)
    return dec['Plaintext'].decode('utf-8')


if __name__ == '__main__':
    confluence_pages()
