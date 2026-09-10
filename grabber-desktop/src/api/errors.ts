// Tauri IPC rejections arrive as objects (typically { message: string }).
// Rendering them with String() produces "[object Object]"; unwrap the
// message instead so screens show the actual backend error.
export function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "object" && e !== null && "message" in e) {
    return String((e as { message: unknown }).message);
  }
  return String(e);
}
