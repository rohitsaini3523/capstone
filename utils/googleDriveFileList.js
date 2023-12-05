import fetch from 'node-fetch';
import fs from 'fs/promises';
import path from 'path';
import zlib from 'zlib';
import { diffLines } from 'diff';
const API_BASE_URL = 'https://www.googleapis.com/drive/v3/files';
let downloadedFiles = new Set();

const createAuthHeader = (accessToken) => ({
    'Authorization': `Bearer ${accessToken}`,
    'Accept': 'application/json',
});

export const fetchFileMetadata = async (accessToken, fileId) => {
    const fileMetadataUrl = `${API_BASE_URL}/${fileId}`;
    const response = await fetch(fileMetadataUrl, {
        method: 'GET',
        headers: createAuthHeader(accessToken),
    });

    if (!response.ok) {
        const errorData = await response.json();
        console.error(errorData);
        throw new Error(`Failed to fetch file metadata: ${response.statusText}`);
    }

    return response.json();
};

const generateDifferentialBackup = (originalData, existingBackupData, originalFileMetadata) => {
    const existingBackupString = zlib.gunzipSync(existingBackupData).toString();

    // Check if there are changes in filesize or modified date
    if (
        originalFileMetadata.size !== existingBackupData.length ||
        originalFileMetadata.modifiedTime !== existingBackupString.split('\n')[0]
    ) {
        console.log('Detected changes in filesize or modified date. Generating differential backup.');

        // Assuming you want to include the differences in content as well
        const originalString = originalData.toString();
        const differences = diffLines(existingBackupString, originalString);
        const patch = differences.map((part) => part.value).join('');
        return zlib.gzipSync(patch);
    } else {
        console.log('No changes in filesize or modified date. Skipping differential backup.');
        return null; // Return null for no changes
    }
};

const performDifferentialBackup = async (filePath, backupFilePath, originalFileMetadata) => {
    try {
        // Check if the file exists before proceeding
        if (!(await fs.access(filePath).then(() => true).catch(() => false))) {
            console.log(`File does not exist: ${filePath}`);
            return;
        }
        const existingBackupData = await fs.readFile(backupFilePath);
        const differentialBackupData = generateDifferentialBackup(
            await fs.readFile(filePath),
            existingBackupData,
            originalFileMetadata
        );

        if (differentialBackupData !== null) {
            await fs.appendFile(backupFilePath, differentialBackupData);
            console.log(`Differential backup updated: ${backupFilePath}`);
        } else {
            console.log('No changes detected. Skipping differential backup.');
        }
    } catch (error) {
        console.error('Differential backup operation failed:', error);
    }
};

const performFullBackup = async (fileId, filePath, backupFilePath) => {
    try {
        await fs.mkdir(path.dirname(backupFilePath), { recursive: true });
        const originalData = await fs.readFile(filePath);
        const gzipData = zlib.gzipSync(originalData);
        await fs.writeFile(backupFilePath, gzipData);
        console.log(`Full backup created: ${backupFilePath}`);
    } catch (error) {
        console.error('Full backup operation failed:', error);
    }
};


const performBackup = async (accessToken, fileId, filePath, backupFolderPath) => {
    if (backupFolderPath === undefined) {
        backupFolderPath = path.join(path.dirname(filePath), 'backup');
    }
    try {
        const backupFilePath = path.join(backupFolderPath, path.basename(filePath));

        if (await fs.access(backupFilePath).then(() => true).catch(() => false)) {
            // Fetch file metadata before calling performDifferentialBackup
            const fileMetadata = await fetchFileMetadata(accessToken, fileId);
            await performDifferentialBackup(fileId, filePath, backupFilePath, fileMetadata);
        } else {
            await performFullBackup(fileId, filePath, backupFilePath);
        }
    } catch (error) {
        console.error('Backup operation failed:', error);
    }
};

export const downloadFile = async (accessToken, fileId, folderPath) => {
    try {
        const fileMetadata = await fetchFileMetadata(accessToken, fileId);
        const filePath = path.join(folderPath, fileMetadata.name);

        if (downloadedFiles.has(filePath)) {
            console.log(`Skipping already downloaded file: ${filePath}`);
            return;
        }

        // Adjust the MIME type based on the file type you are downloading
        const mimeType = fileMetadata.mimeType;
        let exportLink = `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`;

        // Check if the MIME type is an image
        if (mimeType.startsWith('image/')) {
            exportLink += `&mimeType=${mimeType}`;
        }

        const exportResponse = await fetch(exportLink, {
            method: 'GET',
            headers: createAuthHeader(accessToken),
        });

        const fileData = await exportResponse.arrayBuffer();
        await fs.writeFile(filePath, Buffer.from(fileData));

        downloadedFiles.add(filePath);
        const backupFolderPath = path.join(folderPath, 'backup');
        await performBackup(accessToken, fileId, filePath, backupFolderPath);
        // remove the file from the local storage
        await fs.unlink(filePath);
        // store return data in json format in backup folder
        return {
            id: fileId,
            name: fileMetadata.name,
            path: filePath,
        };
    } catch (error) {
        console.error('An error occurred during file download:', error);
        throw new Error('An error occurred during file download.');
    }
};

export const fetchGoogleDriveFileList = async (accessToken, folderPath = '/') => {
    console.log('Fetching Google Drive file list...');
    console.log(`Saving files to ${folderPath}`);
    // Create the folder if it doesn't exist
    await fs.mkdir(folderPath, { recursive: true });
    try {
        const googleDriveFilesUrl = 'https://www.googleapis.com/drive/v3/files';
        const params = {
            q: "trashed=false", // Exclude trashed files
            fields: 'files(id, name, mimeType, modifiedTime, size, parents)',
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

            const fileDownloads = googleDriveFileListData.files.map(async (file) => {
                const filePath = path.join(folderPath, file.name);
                return downloadFile(accessToken, file.id, folderPath, downloadedFiles, file.parents, filePath);
            });

            await Promise.all(fileDownloads);
            console.log('Google Drive file list download complete.');
            return googleDriveFileListData.files;
        } else {
            throw new Error(`Failed to fetch Google Drive file list: ${response.statusText}`);
        }
    } catch (error) {
        console.error(error);
        throw new Error('An error occurred during file list download.');
    }
};

export const fetchGoogleDriveFile_List = async (accessToken, folderPath = '/') => {
    console.log('Fetching Google Drive file list...');
    try {
        const googleDriveFilesUrl = 'https://www.googleapis.com/drive/v3/files';
        const params = {
            q: "trashed=false", // Exclude trashed files
            fields: 'files(id, name, mimeType, modifiedTime, size, parents)',
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
            console.log('Google Drive file list download complete.');
            // console.log(googleDriveFileListData);
            return googleDriveFileListData;
        } else {
            throw new Error(`Failed to fetch Google Drive file list: ${response.statusText}`);
        }
    } catch (error) {
        console.error(error);
        throw new Error('An error occurred during file list download.');
    }
};

const getContentType = (filePath) => {
    const contentTypeMap = {
        '.pdf': 'application/pdf',
        '.txt': 'text/plain',
        '.jpg': 'image/jpeg',
    };

    const fileExtension = filePath.toLowerCase().slice(filePath.lastIndexOf('.'));
    return contentTypeMap[fileExtension] || 'application/octet-stream';
};

const uploadFile = async (accessToken, filePath) => {
    try {
        const fileData = await fs.readFile(filePath);
        const fileMetadata = {
            name: path.basename(filePath),
        };
        const uploadUrl = `${API_BASE_URL}?uploadType=media`;
        const response = await fetch(uploadUrl, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': getContentType(filePath),
            },
            body: fileData,
        });
        if (!response.ok) {
            const errorData = await response.json();
            console.error(errorData);
            throw new Error(`Failed to upload file: ${response.statusText}`);
        }
        console.log('File uploaded successfully:', fileMetadata.name);
    } catch (error) {
        console.error('An error occurred during file upload:', error);
        throw new Error('An error occurred during file upload.');
    }
};

export const performRestore = async (accessToken, filename, backupFilePath) => {
    try {
        const backupFileExists = await fs.access(backupFilePath + filename).then(() => true).catch(() => false);

        if (backupFileExists) {
            console.log(`Local backup file found: ${backupFilePath + filename}`);
            await uploadFile(accessToken, backupFilePath + filename);
            console.log('Restore complete.');
            return true;
        } else {
            console.log('Local backup file not found. Unable to restore.');
        }
    } catch (error) {
        console.error('Restore operation failed:', error);
    }
};