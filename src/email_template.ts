const EmailTemplate = async (filepath: string) => {
  const file = Bun.file(filepath);
  const text = await file.text();

  return (...args: string[]) => {
    if (args.length % 2 !== 0) throw "Invalid template arguments";
    let res = text;
    for (let i = 0; i < args.length; i += 2) {
      res = text.replace(args[i], args[i + 1]);
    }
    return res;
  };
};
export default EmailTemplate;
