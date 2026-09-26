// Ported from defang_text()/refang_text() in src/threatpad.py — same ordering
// matters (URLs and emails must be defanged before the generic dot pass).
export function defangText(input: string): string {
  let text = input;

  text = text.replace(/https:\/\//gi, "hxxps[://]");
  text = text.replace(/http:\/\//gi, "hxxp[://]");

  const emailPattern = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  text = text.replace(emailPattern, (m) => m.replace("@", "[@]"));

  const ipv6Pattern = /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g;
  text = text.replace(ipv6Pattern, (m) => m.replace(/:/g, "[:]"));

  const domainPattern =
    /\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b/g;
  const ipPattern = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;

  text = text.replace(domainPattern, (m) => m.replace(/\./g, "[.]"));
  text = text.replace(ipPattern, (m) => m.replace(/\./g, "[.]"));

  text = text.replace(/#/g, "[#]");
  text = text.replace(/@(?=\[#\])/g, "[@]");
  text = text.replace(/(?<=\[#\])@/g, "[@]");

  return text;
}

export function refangText(input: string): string {
  let text = input;

  text = text.replace(/hxxps\[:\/\/\]/gi, "https://");
  text = text.replace(/hxxp\[:\/\/\]/gi, "http://");

  text = text.replaceAll("[.]", ".");
  text = text.replaceAll("[@]", "@");
  text = text.replaceAll("[:]", ":");
  text = text.replaceAll("[#]", "#");

  return text;
}
