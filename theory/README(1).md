# Discovering vulnerabilities in Python web applications

## 1\. Aims of this project

- To achieve an in-depth understanding of a security [problem](#2-problem).
- To tackle the problem with a hands-on approach, by implementing a tool.
- To analyse a tool's underlying security mechanism according to the guarantees that it offers, and to its intrinsic limitations.
- To understand how the proposed solution relates to the state of the art of research on the security problem.
- To develop collaboration skills.

### Components

The Project is presented in [Section 2](#2-problem) as a problem, and it consists in the development and  evaluation of a tool in Python, according to the [Specification of the Tool](#3-specification-of-the-tool).  It includes an **experimental** component, the development, in groups of three students, of a solution to the problem, and an individual **practical test** [Test](#4-practical-test), that includes an analysis of the solution and a validation of the individual skills associated to its development.

### Important dates and instructions

- Groups of 3 students should register in Fénix by **28 November 2025**. Group members may be registered in different lab sessions, but they need to be registered in some lab.
- The submission deadline for the **code is 9 January 2026, 5pm**.
- Please submit your code via your group's private repository at GitLab@RNL, under the appropriate Group number `https://gitlab.rnl.tecnico.ulisboa.pt/ssof2526/project/project-groups/GroupXX` (_to be created after registration in Fenix_).
- Checklist for code submission:
  - The submissions should include all the necessary code, with all and any configuration in place for executing the tool according to the instructions in [Specification of the Tool](#3-specification-of-the-tool).
  - The tool should be implemented in Python, version >= 3.11.2 and <= 3.12, and require only modules from the standard library, plus `astexport`.
  - All tests that you would like to be considered for the evaluation of your tool should be made available in a common repository `https://gitlab.rnl.tecnico.ulisboa.pt/ssof2526/project/community-tests`. More info [here](https://gitlab.rnl.tecnico.ulisboa.pt/ssof2526/project/community-tests).
  - 5 Python patterns representing real world vulnerabilities.
- The project will have a **practical test** on **13 January 2026**. For this test, students should be able to perform a critical analysis of their solution and answer questions regarding the experimental part of their project, as well as extend or adapt the solution to new requirements.
- **Demonstrations and discussions** regarding the tool and practical test will take place between **12-16 January 2026**.

### Authorship

Projects are to be solved in groups of 3 students. All members of the group are expected to be equally involved in solving, writing and presenting the project, and share full responsibility for all aspects of all components of the evaluation.

All sources should be adequately cited. [Plagiarism](https://en.wikipedia.org/wiki/Plagiarism) will be punished according to the rules of the School.

## 2\. Problem

A large class of vulnerabilities in applications originates in programs that enable user input information to affect the values of certain parameters of security sensitive functions. In other words, these programs encode a potentially dangerous information flow, in the sense that low integrity -- tainted -- information (user input) may interfere with high integrity parameters of sensitive functions **or variables** (so called sensitive sinks). This means that users are given the power to alter the behavior of sensitive functions **or variables**, and in the worst case may be able to induce the program to perform security violations. For this reason, such flows can be deemed illegal for their potential to encode vulnerabilities.

It is often desirable to accept certain illegal information flows, so we do not want to reject such flows entirely. For instance, it is useful to be able to use the inputted user name for building SQL queries. It is thus necessary to differentiate illegal flows that can be exploited, where a vulnerability exists, from those that are inoffensive and can be deemed secure, or endorsed, where there is no vulnerability. One approach is to only accept programs that properly sanitize the user input, and by so restricting the power of the user to acceptable limits, in effect neutralizing the potential vulnerability.

The aim of this project is to study how web vulnerabilities can be detected statically by means of taint and input sanitization analysis. We choose as a target web server side programs encoded in the Python language. There exist a range of Web frameworks for Python, of which Django is the most widely used. While examples in this project specification often refer to Django views, the problem is to be understood as generic to the Python language.

The following references are mandatory reading about the problem:

- S. Micheelsen and B. Thalmann, "PyT - A Static Analysis Tool for Detecting Security Vulnerabilities in Python Web Applications", Master's Thesis, Aalborg University 2016
- V. Chibotaru et. al, "Scalable Taint Specification Inference with Big Code", PLDI 2019 Note: This paper contains a large component of machine learning that is not within the scope of this course, and which you may skip through.
- L. Giannopoulos et. al, "Pythia: Identifying Dangerous Data-flows in Django-based Applications", EuroSec 2019

## 3\. Specification of the Tool

The experimental part consists in the development of a static analysis tool for identifying data and information flow violations that are not protected in the program. In order to focus on the flow analysis, the aim is not to implement a complete tool. Instead, it will be assumed that the code to be analyzed has undergone a pre-processing stage to isolate, in the form of a program slice, a sequence of Python instructions that are considered to be relevant to our analysis.

The following code slice, which is written in Python, contains code lines which may impact a data flow between a certain entry point and a sensitive sink. The variable `request` (which for intuition can be seen as the request parameter of a Django view), is uninstantiated, and can be understood as an entry point. It uses the `mark_safe` function, for rendering templates.

```python
comment = request.GET["comment"]
html_output = mark_safe("<p>%s</p>" % comment)
```

Inspecting this slice it is clear that the program from which the slice was extracted can potentially encode an Cross-site scripting vulnerability. An attacker can inject a malicious comment such as `<script>alert('Hi');</script>`, modifying the structure of the html code so as to execute a command in the browser. However, sanitization of the untrusted input can remove the vulnerability:

```python
comment = request.GET["comment"]
safe_comment = html.escape(comment)
html_output = mark_safe("<p>%s</p>" % safe_comment)
```

The aim of the tool is to search the slices for vulnerabilities according to inputted patterns, which specify for a given type of vulnerability its possible sources (a.k.a. entry points), sanitizers and sinks. A _pattern_ is a 5-tuple with:

- name of vulnerability (e.g., XSS)
- a set of entry points (e.g., `get`),
- a set of sanitization functions (e.g., `escape`),
- a set of sensitive sinks (e.g., `mark_safe`),
- and a flag indicating whether implicit flows are to be considered.

In addition to the entry points specified in the patterns, **by default any non-instantiated variable or field that appears in the slice should be considered as an entry point to all vulnerabilities being considered**.

The tool should signal potential vulnerabilities and sanitization efforts: if it identifies a possible data flow from an entry point to a sensitive sink (according to the inputted patterns), it should report a potential vulnerability; if the data flow **passes through** a sanitization function (in other words, it is returned by the function), _it should still report the vulnerability_, but also acknowledge the fact that its sanitization is possibly being addressed.

Program slices and patterns are provided to assist you in testing the tool. It is however each group's responsibility to perform more extensive testing for ensuring the correctness and robustness of the tool. Have in mind that for the purpose of testing, the names of vulnerabilities, sources, sanitizers and sinks are irrelevant and do not need to correspond to real vulnerabilities. By devising and using code fragments and patterns that cover different situations, this will increase the correctness and robustness of your tool when manage meaningful patterns. See examples in Section [Input Vulnerability Patterns](#vulnerability-patterns).

### Running the tool

The tool should be called in the command line, and receive the following two arguments, and only the following two arguments:

- a path to a Python file containing the program slice to analyse;
- a path to a [JSON](http://www.json.org/) file containing the list of vulnerability patterns to consider.

You can assume that the input files are [well-formed](#program-slices). The analysis should be fully customizable to the inputted [vulnerability patterns](#vulnerability-patterns) described below.

The output should list the potential vulnerabilities encoded in the slice, and an indication of which sanitization functions(s) (if any) have been applied. The format of the output is specified [below](#output).

Your tool should be implemented in **Python, version >= 3.11.2 and <= 3.12** plus `astexport`, require only modules from the standard library, and work in the following way:

1. be named `py_analyser.py`;
2. be called in the command line with two arguments `<path_to_slice>/<slice>.py` and `<path_to_pattern>/<patterns>.json`, in this order;
3. produce the output referred below and no other to a file named `<slice>.output.json` in the `./output/` folder.

For example

    $ python ./py_analyser.py foo/slice_1.py bar/my_patterns.json

should analyse `slice_1.py` slice in folder `foo`, according to patterns in file `my_patterns.json` in folder `bar`, and output the result in file `./output/slice_1.output.json`.

NOTE: Examples of slices, patterns, outputs, and scripts that validate their correct format will be made available.

### Input

#### Program slices

Your program should read from a text file (given as first argument in the command line) the code of a Python slice. See [below](#processing) how you can easily parse it into an Abstract Syntax Tree (AST).

#### Vulnerability patterns

The patterns are to be loaded from a file, whose name is given as the second argument in the command line. You can assume that pattern names are unique within a file.

An example JSON file with two patterns:

    [
      {"vulnerability": "SQL injection A",
      "sources": ["get", "get_object_or_404", "QueryDict", "ContactMailForm", "ChatMessageForm"],
      "sanitizers": ["mogrify", "escape_string"],
      "sinks": ["execute"],
      "implicit": "no"},

      {"vulnerability": "SQL injection B",
      "sources": ["QueryDict", "ContactMailForm", "ChatMessageForm", "copy", "get_query_string"],
      "sanitizers": ["mogrify", "escape_string"],
      "sinks": ["raw", "RawSQL"],
      "implicit": "yes"},

      {"vulnerability": "XSS",
      "sources": ["get", "get_object_or_404", "QueryDict", "ContactMailForm", "ChatMessageForm"],
      "sanitizers": ["clean", "escape", "flatatt", "render_template", "render", "render_to_response"],
      "sinks": ["send_mail_jinja", "mark_safe", "Response", "Markup", "send_mail_jinja", "Raw"],
      "implicit": "no"}
    ]

### Processing

The Python file (given as first argument in the command line) containing the Python slice should be converted into an Abstract Syntax Tree (AST).

You can use Python's `ast` module to obtain a tree of objects whose classes all inherit from [ast.AST](https://docs.python.org/3/library/ast.html). The tool can work directly on this ast using the module's utility functions.

You can also opt to work on a simplified representation of the AST where nodes are represented using dictionaries and lists. To this end, you can use

```python
ast_py = ast.parse(py_str)
ast_dict = astexport.export.export_dict(ast_py)
```

In the above, `py_str` is the string containing the Python code, and `ast_dict` is a dictionary encoding of the ast that represents the code.
The AST is represented in JSON, using the same structure as in [Python's AST module](https://docs.python.org/3.10/library/ast.html).

The structure of Python's ASTs varies slightly with different Python versions. The folllwing examples use are compatible with the Python versions 3.11.2-3.12. For instance, the program

```python
print("Hello World!")
```

is represented in json as

```json
{
  "ast_type": "Module",
  "body": [
    {
      "ast_type": "Expr",
      "value": {
        "ast_type": "Call",
        "func": {
          "ast_type": "Name",
          "id": "print",
          "ctx": {
            "ast_type": "Load"
          },
          "lineno": 1,
          "col_offset": 0,
          "end_lineno": 1,
          "end_col_offset": 5
        },
        "args": [
          {
            "ast_type": "Constant",
            "value": "Hello World!",
            "kind": null,
            "lineno": 1,
            "col_offset": 6,
            "end_lineno": 1,
            "end_col_offset": 20
          }
        ],
        "keywords": [
        ],
        "lineno": 1,
        "col_offset": 0,
        "end_lineno": 1,
        "end_col_offset": 21
      },
      "lineno": 1,
      "col_offset": 0,
      "end_lineno": 1,
      "end_col_offset": 21
    }
  ],
  "type_ignores": [
  ]
}
```

and the slice

```python
comment = request.GET["comment"]
html_output = mark_safe("<p>%s</p>" % comment)
```

is represented in json as:

```json
{
  "ast_type": "Module",
  "body": [
    {
      "ast_type": "Assign",
      "targets": [
        {
          "ast_type": "Name",
          "id": "comment",
          "ctx": {
            "ast_type": "Store"
          },
          "lineno": 1,
          "col_offset": 0,
          "end_lineno": 1,
          "end_col_offset": 7
        }
      ],
      "value": {
        "ast_type": "Subscript",
        "value": {
          "ast_type": "Attribute",
          "value": {
            "ast_type": "Name",
            "id": "request",
            "ctx": {
              "ast_type": "Load"
            },
            "lineno": 1,
            "col_offset": 10,
            "end_lineno": 1,
            "end_col_offset": 17
          },
          "attr": "GET",
          "ctx": {
            "ast_type": "Load"
          },
          "lineno": 1,
          "col_offset": 10,
          "end_lineno": 1,
          "end_col_offset": 21
        },
        "slice": {
          "ast_type": "Constant",
          "value": "comment",
          "kind": null,
          "lineno": 1,
          "col_offset": 22,
          "end_lineno": 1,
          "end_col_offset": 31
        },
        "ctx": {
          "ast_type": "Load"
        },
        "lineno": 1,
        "col_offset": 10,
        "end_lineno": 1,
        "end_col_offset": 32
      },
      "type_comment": null,
      "lineno": 1,
      "col_offset": 0,
      "end_lineno": 1,
      "end_col_offset": 32
    },
    {
      "ast_type": "Assign",
      "targets": [
        {
          "ast_type": "Name",
          "id": "html_output",
          "ctx": {
            "ast_type": "Store"
          },
          "lineno": 2,
          "col_offset": 0,
          "end_lineno": 2,
          "end_col_offset": 11
        }
      ],
      "value": {
        "ast_type": "Call",
        "func": {
          "ast_type": "Name",
          "id": "mark_safe",
          "ctx": {
            "ast_type": "Load"
          },
          "lineno": 2,
          "col_offset": 14,
          "end_lineno": 2,
          "end_col_offset": 23
        },
        "args": [
          {
            "ast_type": "BinOp",
            "left": {
              "ast_type": "Constant",
              "value": "<p>%s</p>",
              "kind": null,
              "lineno": 2,
              "col_offset": 24,
              "end_lineno": 2,
              "end_col_offset": 35
            },
            "op": {
              "ast_type": "Mod"
            },
            "right": {
              "ast_type": "Name",
              "id": "comment",
              "ctx": {
                "ast_type": "Load"
              },
              "lineno": 2,
              "col_offset": 38,
              "end_lineno": 2,
              "end_col_offset": 45
            },
            "lineno": 2,
            "col_offset": 24,
            "end_lineno": 2,
            "end_col_offset": 45
          }
        ],
        "keywords": [
          
        ],
        "lineno": 2,
        "col_offset": 14,
        "end_lineno": 2,
        "end_col_offset": 46
      },
      "type_comment": null,
      "lineno": 2,
      "col_offset": 0,
      "end_lineno": 2,
      "end_col_offset": 46
    }
  ],
  "type_ignores": [
    
  ]
}
```

Note that not all of the information that is available in the AST needs necessarily to be used and stored by your program. This [tutorial](https://greentreesnakes.readthedocs.io/en/latest/) is a helpful resource.

You can produce your own ASTs for testing your program by using a [python-to-json parser](https://pypi.org/project/astexport/). You can visualize the JSON outputs as a tree using [this online tool](http://jsonviewer.stack.hu/).

### Output

The output of the program is a `JSON` list of vulnerability objects that should be written to a file `./output/<slice>.output.json` where `<slice>.js` is the program slice under analysis. The list must include a vulnerability object for every pair source-sink between which there is at least one information flow.  For each of these flows:

- If the flow includes an implicit flow, it must be signaled.
- If the flow is not sanitized, it must be signaled, and if it is, all sanitizers must be identified.

The objects should include 4 pairs, with the following format and meaning:

- `vulnerability`: name of vulnerability (string, according to the inputted pattern)
- `source`: input source (string, according to the inputted pattern, and line where it appears in the code)
- `sink`: sensitive sink (string, according to the inputted pattern, and line where it appears in the code)
- `flows`: list of pair (lists with two elements) where the first component is a string "implicit"/"explicit", according to whether the flow includes an implicit flow or not, and the second component, describing the sanitization that the flow has gone through, is a list of pairs (lists with two elements) where the first component is a sanitizing functions (string, as in an inputted pattern), and the second component is the line number of where it appears in the code (if no sanitition occurs then the list is empty).

As an example, the output with respect to the unsanitized and sanitized programs and patterns that appear in the examples in [Specification of the Tool](#3-specification-of-the-tool) would be:

```json
    [{"vulnerability": "XSS",
    "source": ["get", 1],
    "sink": ["mark_safe", 2],
    "flows": [["explicit", []]]}]
```

and

```json
    [{"vulnerability": "XSS",
    "source": ["get", 1],
    "sink": ["mark_safe", 2],
    "flows": [["explicit", [["escape", 3]]]]}]
```

More precisely, the format of the output should be:

    <OUTPUT> ::= [ <VULNERABILITIES> ]
    <VULNERABILITIES> := "none" | <VULNERABILITY> | <VULNERABILITY>, <VULNERABILITIES>
    <VULNERABILITY> ::= { "vulnerability": "<STRING>",
                        "source": [ "<STRING>", <INT> ]
                        "sink": [ "<STRING>", <INT> ],
                        "flows": [ <FLOWS> ] }
    <FLOWS> ::= <FLOW> | <FLOW>, <FLOWS>
    <FLOW> ::= [ <IMPEXP>, [] ] | [ <IMPEXP>, [<SANITIZERS>] ]
    <IMPEXP> ::= "implicit" | "explicit"
    <SANITIZERS> ::= <SANITIZER> | <SANITIZER>, <SANITIZERS>
    <SANITIZER> ::= [ <STRING>, <INT> ]

### Precision and scope

The security property that underlies this project is the following:

_Given a set of vulnerability patterns of the form (vulnerability name, a set of entry points, a set of sensitive sinks, a set of sanitizing functions), a program is secure if it does not encode, for any given vulnerability pattern, an information flow from an entry point to a sensitive sink, unless the information goes through a sanitizing function._

You will have to make decisions regarding whether your tool will signal, or not, illegal taint flows that are encoded by certain combinations of program constructs. You can opt for an approach that simplifies the analysis. This simplification may introduce or omit features that could influence the outcome, thus leading to wrong results.

Note that the following criteria will be valued:

- _Soundness_ - successful detection of illegal taint flows (i.e., true positives). In particular, treatment of implicit taint flows will be valued.
- _Precision_ - avoiding signalling programs that do not encode illegal taint flows (i.e., false-positives). In particular, sensitivity to the order of execution will be valued.
- Scope - treatment of a larger subset of the language.

Using the same terms as in [Python Parser](https://docs.python.org/3/library/ast.html) the mandatory constructs are those associated with nodes of type

- Expressions
  - Constant
  - Name
  - BinOp, UnaryOp
  - BoolOp, Compare
  - Call
  - Attribute
  - Subscript (assuming a Name as container)
- Statements
  - Expr
  - Assign
  - If
  - While

When designing and implementing this component, you are expected to take into account and to incorporate precision and efficiency considerations, as presented in the critical analysis criteria below.

## 4\. Practical Test

### Critical Analysis

The test will contain questions that evaluate your ability to critically analyse the tool that you have submitted, from the point of view of its precision and scope.

You will be asked to consider the security property expressed in [Precision and scope](#precision-and-scope), and the security mechanism that is studied in this project, which comprises:

- A component (assume already available) that statically extracts the program slices that could encode potential vulnerabilities in a program.
- A tool (developed by you), that receives a configuration file containing vulnerability patterns, and signals potential vulnerabilities in given slices according to those patterns, as well as possible sanitization efforts.

Given the intrinsic limitations of the static analysis problem, the tool you developed in the experimental part is necessarily imprecise in determining which programs encode vulnerabilities or not. It can be unsound (produce false negatives), incomplete (produce false positives), or both. You should be able to:

1. Explain and give examples of what are the imprecisions that are built into the proposed mechanism. Have in mind that they can originate at different levels:
    - imprecise tracking of information flows
        - Are all illegal information flows captured by the adopted technique? (false negatives)
        - Are there flows that are unduly reported? (false positives)
    - imprecise endorsement of input sanitization
        - Are there sanitization functions that could be ill-used and do not properly sanitize the input? (false negatives)
        - Are all possible sanitization procedures detected by the tool? (false positives)
2. _For each_ of the identified imprecisions that lead to:
    - undetected vulnerabilities (false negatives)
        - Can these vulnerabilities be exploited?
        - If yes, how (give concrete examples)?
    - reporting non-vulnerabilities (false positives)
        - Can you think of how they could be avoided?

### Mastering your code

Additionally, you should be able to extend or adapt your tool in order to tackle information flows encoded for different language constructs, or render information about the illegal flows in a different manner.

## 5\. Grading

The project grade will consist of two components: 80% for the tool development (TD), and 20% for the critical analysis (CA).  The practical test will play a role in both of these components.

### Experimental part

**The tool must adhere to the input/output formats specified in this document. Failure to do so may jeopardize/add delays to grading the project**.

The grade for the experimental part (EP) includes automatic and manual evaluation of the Tool and Patterns.  It will reflect the level of complexity of the developed tool, according to the following:

- Basic vulnerability detection (50%) - signals potential vulnerability based solely on explicit flows in slices with mandatory constructs
- Advanced vulnerability detection (25%) - signals potential vulnerability that can include implicit flows in slices with mandatory constructs, including the correct identification of implicit flows
- Sanitization recognition (20%) - signals potential sanitization of vulnerabilities
- Definition of a minimum of 5 appropriate Python Vulnerability Patterns (5%) - consider the provided and other related work. To be submitted in the same repo as the Group's project under name `5_patterns.json`.
- Bonus (5%) - treats other program constructs beyond the mandatory ones, extra effort for avoiding false positives

### Practical Test and Discussion

The practical test is to be performed individually and in person.  It consists of two parts: Implementation Skills (IS) and [Critical Analysis](#critical-analysis) (CA). The first part will validate that each participant in the project group has the implementaiton skills associated to the submitted project.

Students can be selected for a discussion about the project, as decided by the course instructors. For students who are called, the discussion is mandatory in order to be graded for the project.
During the discussion, each student is expected to be able to demonstrate full knowledge of all details of the project. Each individual grade might be adjusted according to the student's performance during the discussion.

### Final Project Grade

The final grade for the project is determined by the formula 0.8*min(EP, IS) + 0.2*CA.

## 6\. Other Materials

Folder [slices/](slices/) contains examples of analysis. For each slice `slice.py` we provide the expected output `slice.output.json` according to vulnerability patterns `slice.patterns.json`.

- [Slices](slices/)
