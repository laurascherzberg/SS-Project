# Community Tests Repository

Welcome to the Community Repository for Testing the Projects of the Software Security course 2025/26.

Note that __this repository is not supervised by the lecturers of the course, hence no guarantees of correctness of the provided examples are provided__. Apply your best judgement when using these tests.

## Submitting a test

If you want to submit a test, just create folder `TXX-NN` where `XX` is your group number and `NN` is the test sequence number for your group.  
For example, the 3rd test submitted by group 47 should be in folder `T47-03`.

1. Add the following files to that folder

   - `<slice>.py` with the Javascript slice to analyse
   - `<slice>.patterns.json` with the patterns to verify  
   - `<slice>.output.json` with the expected output

2. Commit the test to the repository, with a brief commit message explaining the goal of the test.

### Before submitting a test

Before submitting a test please check if it is syntactically correct:

    python validate.py -p <path_to_test>/<slice>.patterns.json -o <path_to_test>/<slice>.output.json

- Option `-p` tests the (syntactic) correctness of the patterns file
- Option `-o` tests the (syntactic) correctness of the output file

## Running a test

To run a test you should run:

    python ./py_analyser.py <path_to_test>/<slice>.py <path_to_pattern>/<slice>.patterns.json

where

- `<path_to_test>` is the path to the test folder you want to use (e.g., `T47-03`).

## Checking equality of output

You can also use `validate.py` to check the equality of your output (`-o`) with respect to the intended one (`-t`) (notice that the order of the lists may differ hence `diff` may return incorrect results). To compare your result with the one in `<path_to_test>/<slice>.output.json` use:

    python validate.py -o <path_to_your_output>/<slice>.output.json -t <path_to_test>/<slice>.output.json

If you want to test __partial solutions__ you can also use the flags

- `--ignore_lines`, that does not verify if the lines of the instructions match between your output and the expected one;
- `--ignore_implicit`, that does not verify if the `implicit` output is correct (nor even if it is present);
- `--ignore_sanitizers`, that does not verify if the `sanitized_flows` list match.

## Spotting incorrect Outputs/Mistakes

In case you find a mistake, please submit an issue detailing the error and assign it to the person that submitted the original test.

If it is clear that it is an error, you can also submit a pull request with the fix and commit message `fixes #Y` where Y is the issue number.
