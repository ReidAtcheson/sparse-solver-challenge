# What the three-band proof certifies

The public challenge fixes a signed symmetric matrix $A$ and a right-hand side $b_i=\sigma_i/n$, where each $\sigma_i$ is $+1$ or $-1$. Its authenticated profile ID is `signed-three-band-backward80-v1`. The row count $n=2^\ell$ ranges from 1,024 to 65,536. The generator accepts singular draws as issued. A proof certifies the residual of one committed vector whether the system has a unique solution, many solutions, or none. [Matrix generator](THREE_BAND.md)

## Reading the validator's score

The validator prints the exact integer squared residual $\rho$, the exact integer squared solution norm $Q$, and the shared exponent $E$. In physical units the solution is $x=2^{E-78}X$. Define $h=2^{78-E-\ell}$. Scaling each residual by $2^{78-E}$ gives the integer vector $R=AX-h\sigma$, so

$$
  Q=\sum_j X_j^2,\qquad \rho=\sum_i R_i^2,\qquad
  \frac{\|Ax-b\|_2}{\|b\|_2}=\frac{\sqrt{\rho}}{h\sqrt n}.
$$

Every matrix has $7n-12$ unit-magnitude entries. Its Frobenius norm squared is $7n-12$, the sum of the squares of its $n$ singular values. The largest squared singular value is at least their average. With $L=\sqrt{(7n-12)/n}$, this gives

$$
  \underbrace{\frac{\|Ax-b\|_2}{\|A\|_2\,\|x\|_2+\|b\|_2}}_{\text{joint normwise backward error}}
  \;\le\;
  \underbrace{\frac{\sqrt{\rho}}{L\sqrt{Q}+h\sqrt n}}_{\texttt{backward\_2\_upper}}.
$$

The challenge requires the right-hand quantity to be at most $2^{-53}$. A pass certifies that accuracy for the joint backward error. A miss means the conservative threshold was exceeded. The printed decimal is rounded. For the exact decision, set $D=2^{106}\rho n$, $U=(7n-12)Q$, and $V=h^2 n^2$. The inequality $\sqrt D\le\sqrt U+\sqrt V$ holds precisely when $d=D-U-V\le0$ or $d^2\le4UV$. The validator computes this comparison with integers. [Scoring code](protocol.c)

## Checking the generator without receiving the solution

The two sumchecks reduce the residual and norm claims to an opening of the committed $X$ and a public matrix evaluation. At the final points, write $u_i$ and $v_j$ for the row and column interpolation weights. To compute $\sum_{ij}u_i A_{ij}v_j$, the validator regenerates each strict-upper entry $(i,j,s)$ once and adds $s(u_i v_j+u_j v_i)$. For a diagonal entry it adds $s u_i v_i$ once. It separately computes $\sum_i u_i\sigma_i$ from the public RHS generator. The row commitments and folded opening in the transcript authenticate the private vector's contribution. [Endpoint code](operator.c) · [Opening and sumcheck argument](SOUNDNESS.md)

The validator holds $O(\sqrt n)$ interpolation weights and the generator's $O(n)$ incoming-edge counters. Counters start at one byte per column and widen if any counter overflows. The reference sampler consumes random draws for every future column, so regenerating this graph costs $O(n^2)$ time. The prover regenerates the pattern once and caches a packed sparse matrix for its two matrix passes. It releases that cache after constructing the transposed product. Each sumcheck uses a private scratch file of at most $32n$ bytes. The validator needs neither the private solution file nor any matrix file.

## Integer lifting

The range and commitment argument establishes $|X_j|\le 2n2^{78}$ except with its stated soundness error. Thus the ordinary value of $Q$ is at most $4n^3 2^{156}\le2^{206}$, below the scalar field order $q>2^{252}$. The validator checks the authenticated integer $Q\le n 2^{156}$. Hence $\|X\|_2\le2^{86}$. The signed exponent satisfies $-\ell-30\le E\le54$, so $h$ is an integer between $2^8$ and $2^{108}$. Using the Frobenius norm this time as an *upper* bound gives

$$
  \|R\|_2 \le \sqrt{7n-12}\,\|X\|_2+h\sqrt n
             <2^{10}2^{86}+2^{108}2^8 < 2^{117}.
$$

Consequently $\rho<2^{234}<q$. An authenticated field energy gives the ordinary integer energy even when the numerical score misses. The assumptions governing authentication, range tests, and noninteractive sumchecks are given in the [soundness analysis](SOUNDNESS.md).

The local transcript uses the shared-exponent wire format. For width $w=2^{\lfloor\ell/2\rfloor}$ and height $t=n/w$, its complete length including the two signed receipts is $32(w+t)+128\ell+2508$ bytes. The external format carries a variable-size RFC 3161 timestamp response. The profile ID in the authenticated start binds the generator and scoring rule in both formats. [Wire formats](REFERENCE.md#transcript-and-soundness-assumptions) · [External receipts](BEACON.md)
