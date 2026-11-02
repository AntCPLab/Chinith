This is an open-sourced sm4ni implementation from https://github.com/mjosaarinen/sm4ni.

It uses affine transformations and AES NI to implement the SM4 S-Box.

It provides a 4-block encryption acceleration in [sm4_encrypt4_opt](sm4ni.c).