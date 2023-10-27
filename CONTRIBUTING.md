# Contributing to capyCRYPT
If you want to learn about rust, cryptography, high-performing software, and formal software design patterns, you're in the right place! This library is an academic excerise in cryptographic algorithm design and is a great place for anyone who is just getting started with their career in software development. 

NO EXPERIENCE IS NECESSARY to contribute to this library. We gladly welcome anyone who wants to tackle any of the open issues. Cryptography is a dense subject. You might feel like you jumped into the deep end of the pool. And the pool isn't filled with water but gasoline instead. And it's on fire! But what better way is there to learn? 

Some things to remember as you go through the code:
1. If you haven't seen rust before, some of the syntax might look a little wild. Don't be intimidated! Rust is a wonderful, logical, and great language to have in your toolbox. The maintainers of this repo are here to help you whenever you need it, reach out with any question at any time!
2. Contributing to open-source libraries is a fantastic item to add to your resume and can help give you a competitive advantage in an otherwise difficult job market.
3. Generative AI is your friend. It is extremely adept at explaining code, writing boilerplate, and translating between programming languages. If you're stuck on something, write it in python and then convert it! There's nothing wrong with using sophisticated tools to help you gain experience and understanding.

Example prompts: 
-"Show how to work with arrays in rust"
-"Explain the &mut keyword"
-"What is a trait and why should I use it?"
-"What are effective strategies to reduce memory usage when working with large data?"

## Getting Started

Before you begin, ensure you have a **[GitHub](https://github.com/)** account set up.

1. **Fork** the repository by clicking the "Fork" button at the top-right corner of the original repository page.
2. **Clone** your forked version of the repository to your local machine:
   ```sh
   git clone https://github.com/your-username/capyCRYPT.git
   cd capyCRYPT
   ```
3. Open the repository in your IDE of choice. Assuming you've selected an issue to tackle, create a new branch by using this format:
    - Issues labeled "feature" should have the branch named "feature/issue-#" 
    - Issues labeled "fix" should have the branch named "fix/issue-#" 
    - where "#"" is the number of the issue you are working on.
    - Ex: for issue "fix: Revert a failed decryption #26", the branch should be named fix/issue-26
4. When you have a solution ready for review, make sure all of the tests built into the repo are passing by running: 
   ```sh
   cargo test
   ```
   This could take awhile to run all of them, but ensure they pass before proceeding. If any fail and you are unsure why or need help troubleshooting, ask for help! This is something you'll be expected to do in your job someday, so practice it here!
5. If all tests are passing, run clippy: 
   ```sh
   cargo clippy
   ```
   Clippy is a great friend who helps you learn idiomatic rust. It will point you to all of the places in your code needing attention and will provide you with the best solutions to keep everything neat, clean, and readable.
6. If all tests are passing, run the formatter next: 
    ```sh
    cargo fmt
    ```
   This is crucial to keep the code nice and clean. It fixes spacing and other small housekeeping items automatically.
   
7. Make a pull request of your branch back into main/master. This step initates review with the maintainers. A review process is often a conversation between a maintainer and a developer. Don't always expect a merge on your first try. Be grateful for the experience to collaborate and learn the best practices to  follow. Larger issues can be merged in parts, so long as they are organized in a way that clearly tracks what is completed and what is left to do.

8. Log your progress on the issue page! Use it as a diary to help keep yourself and others organized. Maintainers can join the conversation with you and help move you along towards the finish line.

Merged PRs, even small ones, are awesome resume material. You can count it as freelancing job experience and it's always a great conversation piece during interviews (and sometimes on dates, with the right person). That's the end of this guide! You are constantly encouraged to ask questions and engage with the development process. This is a risk-free place to develop those skills early so you don't have to scramble to learn them on the job. Good luck!
