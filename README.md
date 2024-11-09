# EUCLID Simulator

This repository contains a custom implementation of the EUCLID algorithm proposed of:

```bibtex
@Article{Euclid,
  author    = {Ilha, A. S. and Lapolli, \^{A}. C. and Marques, J. A. and Gaspary, L. P.},
  journal   = {IEEE Transactions on Network and Service Management},
  title     = {{Euclid: A Fully In-Network, P4-Based Approach for Real-Time DDoS Attack Detection and Mitigation}},
  year      = {2021},
  month     = {sep},
  number    = {3},
  pages     = {3121--3139},
  volume    = {18},
  doi       = {10.1109/TNSM.2020.3048265},
  publisher = {Institute of Electrical and Electronics Engineers ({IEEE})},
}
```

## Details

This implementation relies on the custom file format created to be used for these experiments.

These custom files are then completely mapped to memory so that it speeds up the experiments execution time.

Please note that it requires a fairly substantial amount of RAM memory (dependent on the size of the dataset).
Therefore, if the datasets are larger than the amount of RAM available, it will require some changes to be applied to
the MappedFile class defined in ```tool/common/``` library.
