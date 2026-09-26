// File System Access API is Chromium-only; every entry point here falls back
// to the classic <input type=file> / Blob-download approach in other browsers.

export const hasFileSystemAccess =
  typeof window !== "undefined" && "showOpenFilePicker" in window && "showSaveFilePicker" in window;

const TEXT_TYPES: FilePickerAcceptType = {
  description: "Text files",
  accept: {
    "text/plain": [".txt", ".log", ".md", ".csv", ".json"],
  },
};

export interface OpenedFile {
  name: string;
  content: string;
  handle?: FileSystemFileHandle;
}

/** Heuristic mirror of threatpad.py's UnicodeDecodeError guard on drag/drop. */
export function looksBinary(text: string): boolean {
  return text.includes("\u0000");
}

export async function pickAndOpenFile(): Promise<OpenedFile | null> {
  if (hasFileSystemAccess) {
    try {
      const [handle] = await window.showOpenFilePicker({ types: [TEXT_TYPES] });
      const file = await handle.getFile();
      const content = await file.text();
      if (looksBinary(content)) throw new Error(`Cannot open binary file: ${file.name}`);
      return { name: file.name, content, handle };
    } catch (e) {
      if ((e as DOMException)?.name === "AbortError") return null;
      throw e;
    }
  }
  return null; // caller falls back to the hidden <input type=file>
}

export async function openFromInputFile(file: File): Promise<OpenedFile> {
  const content = await file.text();
  if (looksBinary(content)) throw new Error(`Cannot open binary file: ${file.name}`);
  return { name: file.name, content };
}

/** Writes directly back to an existing handle — a true in-place "Save". */
export async function writeToHandle(handle: FileSystemFileHandle, content: string): Promise<void> {
  const writable = await handle.createWritable();
  await writable.write(content);
  await writable.close();
}

/** "Save As" — always prompts for a location when the API is available. */
export async function pickAndSaveFile(
  suggestedName: string,
  content: string,
): Promise<FileSystemFileHandle | null> {
  if (hasFileSystemAccess) {
    try {
      const handle = await window.showSaveFilePicker({ suggestedName, types: [TEXT_TYPES] });
      await writeToHandle(handle, content);
      return handle;
    } catch (e) {
      if ((e as DOMException)?.name === "AbortError") return null;
      throw e;
    }
  }
  return null; // caller falls back to Blob download
}

/** Attempts to read a dropped item via its live FileSystemFileHandle (Chromium), else falls back to a plain File. */
export async function openFromDataTransferItem(item: DataTransferItem): Promise<OpenedFile | null> {
  const getAsHandle = (item as unknown as { getAsFileSystemHandle?: () => Promise<FileSystemHandle> })
    .getAsFileSystemHandle;
  if (getAsHandle) {
    const handle = await getAsHandle.call(item);
    if (handle.kind === "file") {
      const fileHandle = handle as FileSystemFileHandle;
      const file = await fileHandle.getFile();
      const content = await file.text();
      if (looksBinary(content)) throw new Error(`Cannot open binary file: ${file.name}`);
      return { name: file.name, content, handle: fileHandle };
    }
    return null;
  }
  const file = item.getAsFile();
  if (!file) return null;
  return openFromInputFile(file);
}
