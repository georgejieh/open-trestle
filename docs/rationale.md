# Design rationale

This page gives the reasons behind four of Open Trestle's design choices. Other
pages state what Open Trestle does and link here for the reason.

## Local models and zero-data-retention providers are recommended

A review sends source code to a model: the changed code, context from the
repository around the change, and the commit messages. The
[privacy](privacy.md) page lists the details. Open Trestle recommends routes
where that code is not kept afterwards, for three reasons.

- With a model server on your own machine, Open Trestle sends the review only
  to a loopback address on that machine. What happens to it afterwards is up to
  a server that you run.
- With zero data retention (ZDR) on OpenRouter, the request is routed only to
  endpoints whose providers do not routinely store prompts or responses.
  OpenRouter's [ZDR documentation](https://openrouter.ai/docs/guides/features/zdr)
  lists the exceptions.
- The secret scanner that checks every review request is a
  pattern scanner and misses some credential formats, so a secret in the
  reviewed code can reach the provider. The less a route retains, the less a
  missed secret costs.

For these reasons the setup wizard offers ZDR as the default on OpenRouter when
both models have a ZDR endpoint, and asks you to confirm before it continues
without it.

## Providers without zero data retention still work

ZDR is a recommendation, not a condition of use.

- Not every model has a ZDR endpoint, and a review needs two models.
- Open Trestle sends a ZDR requirement only to OpenRouter. On the other remote
  providers it supports, retention is governed by the provider's terms and your
  account settings.
- Some people use one provider or one plan for every tool they run, and a
  reviewer that refused it would be of no use to them. Signing in with a
  ChatGPT plan, which is on the [roadmap](roadmap.md), is a route of this kind.

When an OpenRouter route does not require ZDR, the review output says so. The
choice stays with you.

## The checker should come from a different model family

One model, the finder, proposes problems, and a second model, the checker,
confirms each one, rejects it or marks it inconclusive. Setup requires the
checker to be a different model and recommends one from a different model
family. Two published results motivate the recommendation.

- A study of more than 350 models found that errors are more correlated between
  models that share a developer or an architecture
  ([Kim et al., 2025](https://proceedings.mlr.press/v267/kim25e.html)). If that
  holds for code review, a checker from the finder's family is more likely to
  share the finder's mistakes and confirm them.
- A study of models used as evaluators found that they can recognize their own
  output and tend to score it higher
  ([Panickssery et al., 2024](https://arxiv.org/abs/2404.13076)).

Neither study tested code review. The first also found that the most accurate
models make correlated errors even across developers, so a second family may
reduce shared mistakes but does not remove them. Open Trestle has not yet
measured the effect on its own reviews, which is why the checker's family is
recommended and not required.

## Scripted checks run before model judgment

Open Trestle analyses the change with scripted checks before it asks a model
anything, and gives the results to the models. The [architecture](architecture.md#canonical-flow)
page lists which of these checks exist today.

- A check with fixed rules gives the same answer for the same input, so its
  result can be reproduced and tested. A model's answer can change between
  runs.
- Running a scripted check uses no model tokens.
- Text in the reviewed repository cannot talk a script into following different
  instructions. A model reads that text, and although Open Trestle presents it
  to the model as data, no instruction can guarantee that a model treats it
  that way. See the [prompt-injection boundary](prompt-injection-boundary.md).
- The models are meant to start from checked results and not from guesses. The
  checker also receives the same code the finder saw, and judges each finding
  against it.
