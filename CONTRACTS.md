# How the residual certificate fits together

The certificate uses the same sumcheck twice. The first use leaves one question about the residual. The second use answers that question provided it can read one value of the stamped solution. The row commitment supplies exactly that read.

## The claim and the contracts

Let $X$ be the committed solution vector, with $n$ entries. Use $A$ and $b$ for the public matrix and right-hand side **in integer residual units**. This absorbs the fixed-point scale factors into the public inputs. Define the true residual to be $R=AX-b$ and let $\rho$ be the prover's claimed squared residual. For now, all equalities are in the proof's scalar field. Integer interpretation comes at the end.

For any table $T$, write $T[p]$ for its multilinear evaluation at a point $p$. This means folding pairs in the table using the successive coordinates of $p$ until one value remains. The same operation can be written as a weighted sum of the original table. The weights are determined entirely by $p$.

| Component | What the verifier has | What remains to be established after its checks |
|---|---|---|
| Residual norm | The claimed score $\rho$ and the norm sumcheck messages | At the row challenge $u$, the prover's scalar $y$ must equal $R[u]$. |
| Sparse matvec | That same $u,y$, public $A,b$, and the second sumcheck's messages | At the column challenge $v$, the solution value used in the final product must equal $X[v]$. |
| Commitment opening | That same $v$, the digest-checked row commitments, and one folded row from the prover | The verifier checks a group equality and computes an authenticated scalar $X[v]$. This closes the last obligation. |

The first two rows are **reductions**. Each replaces a claim by a smaller obligation. The last row is a **check** against evidence fixed earlier. The prover sends the messages from top to bottom. To see why acceptance implies a correct score, read the contracts from bottom to top.

One way to test the boundaries is to imagine giving the verifier more information. Give it the true residual array and it could evaluate $R[u]$ itself after the first sumcheck. Give it only the true solution array and it could evaluate $X[v]$ itself after the second sumcheck. In the actual protocol it has neither array, so it uses the opening. Each substitution changes who answers one question. The component asking the question can keep exactly the same checks.

## One reusable sumcheck rule

**Precondition.** A mathematical table expression is fixed before the round challenges. The verifier knows its degree bound and has a way to check its value at the final challenge point. Here the expressions are products of two multilinear factors, so the degree in each individual variable is at most two.

**Postcondition.** A false total can pass with a correct final evaluation only if at least one round draws an exceptional challenge.

**Proof.** At a round, the prover sends a polynomial whose values at 0 and 1 must add to the current claim. There is also a true round polynomial obtained by summing the fixed expression over the remaining address bits. If the current claim is false, these polynomials differ. Two distinct polynomials of degree at most two agree at at most two field elements. A fresh challenge therefore carries the false claim forward except at those values. At the last round, a false claim that survived disagrees with the checked endpoint. For a field of size $q$ and $L=\log_2 n$ independent uniform interactive challenges, the error is at most $2L/q$ per sumcheck. [Sumcheck loop](PROVER.md#the-two-sumchecks-use-the-same-loop)

“Fixed” here describes the **true expression** used to judge the messages. Once $X,A,b$ are fixed, $AX-b$ is mathematically determined even if a dishonest prover fills its scratch file with something else.

## How each component meets the next one's precondition

### 1. What the norm check needs

On Boolean row indices, multiplying the entries of $R$ by themselves and summing gives the desired score. Apply the sumcheck rule to the expression whose value at a row point $u$ is $(R[u])^2$. The verifier checks its terminal scalar against $y^2$, using the $y$ the prover supplies. **If a later check establishes $y=R[u]$, the norm check has the correct endpoint and the rule applies.** The square alone leaves the sign of $y$ unresolved.

### 2. What the matvec check supplies

Let $e$ be the vector of row weights determined by $u$. Thus $R[u]=e^\mathsf T R$. Let $a=A^\mathsf T e$, a public vector with one entry per matrix column. Ordinary distributivity gives the exact equivalence

$$
y=R[u]\quad\Longleftrightarrow\quad
y+e^\mathsf T b=\sum_j a_j X_j .
$$

This step introduces no probability of error. It specifies the **target** for the second sumcheck. Its Boolean sum is the dot product on the right. Its value at the final column point $v$ is the product $a[v]X[v]$, since the prover folds the two factors separately.

The verifier can compute $e^\mathsf T b$ and $a[v]$ by scanning the public generator. Each matrix nonzero contributes its value times one public row weight and one public column weight to $a[v]$. **If the opening supplies the true $X[v]$, this second sumcheck has the correct endpoint.** Its conclusion is precisely the signed equality $y=R[u]$ needed above. [Public endpoint calculation](operator.c)

### 3. What the opening supplies

Let $D$ be $X$ reshaped into a rectangular table. Let $G$ be the column of public group generators, one per table column. The stamped row points are $C=DG$. Split the coordinates of $v$ according to the layout. Write $r$ for the resulting row weights and $c$ for the column weights. Multilinear interpolation gives $X[v]=r^\mathsf T D c$.

The prover sends an ordinary row $z$. The verifier first **requires** $zG=r^\mathsf T C$ and only then returns the scalar $zc$. The honest folded row $r^\mathsf T D$ passes because $(r^\mathsf T D)G=r^\mathsf T(DG)$. A different passing row would give a nonzero vector $z-r^\mathsf T D$ whose product with $G$ is the identity group element. Under the generator relation-hardness assumption, this authenticates the returned scalar. The group check and the field calculation are adjacent in the C verifier. [Verifier](protocol.c) · [Group check](commit.c)

**Composition.** Start with this authenticated scalar. Substitute it into the matvec endpoint to justify $y$. Substitute that same $y$ into the norm endpoint to justify $\rho$. The use of the same $u$ and $y$ across the two reductions, and the same $v$ at the opening, is essential. This proves field soundness for the core residual claim, subject to the opening assumption and the two sumcheck errors.

## What the production protocol adds

| Component | Precondition | Postcondition and reason |
|---|---|---|
| Timestamp | A trusted issuer, the registered start, and one fresh finish for the submitted digest | A valid receipt authenticates receipt of the digest by the recorded time. Rehashing the shape, scale, and row points links their bytes to that digest. Using a single fixed $X$ in the argument additionally needs commitment binding and the extraction argument. |
| Batching | The residual endpoint $y$, the claimed sum of squared solution entries $Q$, and the 128 reported subset sums are fixed before the batching coefficients | The second sumcheck authenticates all these claims together. If the claims have errors, their combined error is an affine function of the fresh coefficients. A nonzero slope permits cancellation for at most one value of its coefficient. A nonzero constant cannot cancel. |
| Range and integer lifting | The same $X$ was fixed before the mask draw. The subset sums and $Q$ have been authenticated, and the verifier checks their bounds. | If a coordinate's centered magnitude exceeds twice the allowed subset-sum magnitude, toggling its bit makes at least one of the two sums fall outside the allowed interval. All 128 independent ideal masks miss this with probability at most $2^{-128}$. The resulting coordinate bound makes the true integer $Q$ smaller than the field order. The verified tighter cap on $Q$ and the public bounds on $A,b$ then make the true integer residual energy smaller than the field order too. |
| Numerical decision | Both energies are exact integers and the profile supplies bounds on the matrix norm and the exact RHS norm | The three-band validator compares a certified upper bound on joint backward error with $2^{-53}$ using integer arithmetic. A valid transcript can certify either a pass or a miss. |

To see **why batching still needs only one opening**, let $M_i$ be the public mask for subset $i$, let $t_i$ be its reported sum, and let $\beta_i$ be its random coefficient. Write $\lambda$ for the random coefficient of $Q$. With $a=A^\mathsf T e$ as above and $i$ running over all 128 masks, the second sumcheck folds the two factors

$$
X \qquad\text{and}\qquad W=a+\sum_i\beta_i M_i+\lambda X .
$$

The claimed dot product is $y+e^\mathsf T b+\sum_i\beta_i t_i+\lambda Q$. At $v$, the verifier already has public evaluations of $a$ and the masks. The **same** authenticated $X[v]$ supplies the private part of $W[v]$ and the first factor in $X[v]W[v]$.

For the three-band profile, the allowed subset magnitude is $T=n2^{78}$ and $n\le2^{16}$. The coordinate bound $2T$ gives $\sum_j X_j^2\le n(2T)^2\le2^{206}<q$. The verifier then enforces $Q\le n2^{156}$, giving $\|X\|_2\le2^{86}$. The Frobenius norm bounds $\|A\|_2$ above by $\sqrt{7n-12}$. Combining this with the RHS scale gives $\rho<2^{234}<q$. Both authenticated energies therefore have their ordinary integer interpretation. [Derivation and numerical decision](THREE_BAND_PROOF.md)

For one ideal interactive attempt with a fixed witness, genuine receipts, independent masks and an authentic opening, the two sumchecks and batching contribute at most $(4L+1)/q$ in total. Add $2^{-128}$ for the range test. The deployed transcript derives its challenges by Fiat–Shamir and expands masks from a public receipt-derived seed. Its conditional security argument includes those mechanisms, the issuer, the digest, and the cost of extracting a witness at the stamp request. [Full soundness analysis](SOUNDNESS.md)
