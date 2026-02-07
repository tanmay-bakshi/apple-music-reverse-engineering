# Reverse Engineering Apple Music APIs

The goal of this project is to reverse engineer as much as we can about the Apple Music APIs — particularly focusing around albums, songs, artists, metadata, lyrics, etc. — purely through static analysis of its macOS application's executable binary.

Along the way, you should continuously and very frequently update a `HISTORY.md` file with your latest thoughts, ideas, hypotheses, observations, the results of your experiments, etc. This file will then be used in the future to construct educational material that walks developers through the whole experimental process, covering every aspect of your journey.

Make frequent Git commits as you progress, and work with the user collaboratively as you reach new milestones to help choose the right direction for further progress.

You are running within a macOS environment. You can use the internet for research, but not to cheat and discover details about Apple Music's internals without discovering it yourself.

# ExecPlans

When writing complex features or significant refactors, use an ExecPlan (as described in .agent/PLANS.md) from design to implementation.
