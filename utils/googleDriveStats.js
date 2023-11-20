import fetch from 'node-fetch';

export async function fetchGoogleDriveStats(accessToken) {
    const googleDriveStatsUrl = 'https://www.googleapis.com/drive/v3/about';
    const params = {
        fields: 'storageQuota',
    };

    const url = new URL(googleDriveStatsUrl);
    url.search = new URLSearchParams(params).toString();

    const response = await fetch(url, {
        method: 'GET',
        headers: {
            'Authorization': 'Bearer ' + accessToken,
            'Accept': 'application/json',
        },
    });

    if (response.ok) {
        const googleDriveStatsData = await response.json();
        return googleDriveStatsData;
    } else {
        throw new Error(`Failed to fetch Google Drive stats: ${response.statusText}`);
    }
}
