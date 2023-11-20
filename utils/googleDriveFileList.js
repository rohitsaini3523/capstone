import fetch from 'node-fetch';

export async function fetchGoogleDriveFileList(accessToken) {
    const googleDriveFilesUrl = 'https://www.googleapis.com/drive/v3/files';
    const params = {
        fields: 'files(name,size)',
    };

    const url = new URL(googleDriveFilesUrl);
    url.search = new URLSearchParams(params).toString();

    const response = await fetch(url, {
        method: 'GET',
        headers: {
            'Authorization': 'Bearer ' + accessToken,
            'Accept': 'application/json',
        },
    });

    if (response.ok) {
        const googleDriveFileListData = await response.json();
        return googleDriveFileListData.files;
    } else {
        throw new Error(`Failed to fetch Google Drive file list: ${response.statusText}`);
    }
}
