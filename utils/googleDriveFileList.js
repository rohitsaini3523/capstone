import fetch from 'node-fetch';
import fs from 'fs/promises';
import fs1 from 'fs';
import path from 'path';
import zlib from 'zlib';
import { diffLines } from 'diff';
import { google } from 'googleapis';

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "928388932838-6n58nnred0umaetr2bm2t44511ucl0vv.apps.googleusercontent.com";
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "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";
const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || "https://developers.google.com/oauthplayground";
const Refresh_Token = "1//044Cx_nBOoFTUCgYIARAAGAQSNwF-L9Ire-8lZs8FmrHfXqM7VOv_x5uq7dMfAP47NjMbTXmHvtsavLow5mv5o1MsUnbJQjX7RgE";
const oauth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
oauth2Client.setCredentials({ refresh_token: Refresh_Token });

const drive = google.drive({
    version: 'v3',
    auth: oauth2Client,
});

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
    // Check if there are changes in filesize or modified date
    if (
        originalFileMetadata.size !== existingBackupData.length ||
        originalFileMetadata.modifiedTime !== existingBackupData.toString('utf-8').split('\n')[0]
    ) {
        console.log('Detected changes in filesize or modified date. Generating differential backup.');
        const patch = createDifferentialPatch(originalData, existingBackupData);
        return zlib.gzipSync(patch);
    } else {
        console.log('No changes in filesize or modified date. Skipping differential backup.');
        return null; // Return null for no changes
    }
};

const createDifferentialPatch = (originalData, existingBackupData) => {
    const originalString = originalData.toString('utf-8');
    const existingBackupString = existingBackupData.toString('utf-8');
    const differences = diffLines(existingBackupString, originalString);
    const patch = differences.map((part) => part.value).join('');
    return patch;
};

const performDifferentialBackup = async (filePath, backupFilePath, originalFileMetadata) => {
    try {
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

const performFullBackup = async (filePath, backupFilePath) => {
    try {
        await fs.mkdir(path.dirname(backupFilePath), { recursive: true });
        const originalData = await fs.readFile(filePath);
        const compressedData = zlib.gzipSync(originalData);
        await fs.writeFile(backupFilePath, compressedData);
        console.log(`Compressed full backup created: ${backupFilePath}`);
    } catch (error) {
        console.error('Compressed full backup operation failed:', error);
    }
};


const performBackup = async (accessToken, fileId, filePath, backupFolderPath) => {
    try {
        const backupFilePath = path.join(backupFolderPath, path.basename(filePath));
        const originalFileMetadata = await fetchFileMetadata(accessToken, fileId);
        // check the modifiedTime from the metadata and compare with the backup file

        if (fs1.existsSync(backupFilePath)) {
            console.log(`Backup file already exists: ${backupFilePath}`);
            await performDifferentialBackup(filePath, backupFilePath,originalFileMetadata);
        }  
        else {
            await performFullBackup(filePath, backupFilePath);
        }
        // shift file to backup folder
        console.log(`File moved to backup folder: ${backupFilePath}`);
    } catch (error) {
        console.error('Backup operation failed:', error);
    }
};


export const downloadFile = async (accessToken, fileId, folderPath) => {
    try {
        const fileMetadata = await fetchFileMetadata(accessToken, fileId);
        const filePath = path.join(folderPath, fileMetadata.name);
        const exportLink = `https://www.googleapis.com/drive/v3/files/${fileId}?alt=media`;
        const exportResponse = await fetch(exportLink, {
            method: 'GET',
            headers: createAuthHeader(accessToken),
        });

        const fileData = await exportResponse.buffer(); // Use buffer() to get binary data
        await fs.writeFile(filePath, fileData);
        downloadedFiles.add(filePath);
        await performBackup(accessToken,fileId, filePath, folderPath);
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

const uploadFile = async (filePath) => {
    try {
        const createFile = await drive.files.create({
            requestBody: {
                name: path.basename(filePath),
                mimeType: getContentType(filePath),
            },
            media: {
                mimeType: getContentType(filePath),
                body: fs1.createReadStream(filePath),
            }
        });
        console.log(createFile.data);
    } catch (error) {
        console.error('An error occurred during file upload:', error);
    }
};


export const performRestore = async (filename, backupFilePath) => {
    try {
        // console.log('filename', filename);
        // console.log('backupFilePath', backupFilePath);
        const backupFileExists = await fs.access(backupFilePath + filename).then(() => true).catch(() => false);
        console.log('Performing restore operation...');
        console.log(`Restoring file: ${backupFilePath + filename}`);
        if (backupFileExists) {
            console.log(`Local backup file found: ${backupFilePath + filename}`);
            await uploadFile(backupFilePath + filename);
            console.log('Restore complete.');
            return true;
        } else {
            console.log('Local backup file not found. Unable to restore.');
        }
    } catch (error) {
        console.error('Restore operation failed:', error);
    }
};