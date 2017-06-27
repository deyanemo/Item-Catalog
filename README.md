# Catlog Item

a project for fullstack developer nanodegree Udacity

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

a python module that create ,edit delete items and categories stored in a database , user login and registration , google sign in button using google+ API


### Prerequisites

What things you need to install the software and how to install them

```
Virtual box
Vagrant
python 2.7x

```

### Installing

A step by step series of examples that tell you have to get a development env running

After installing the Prerequisites

open a terminal and :
(it will take a while)

```
vagrant up

```

after that ssh to the virtual machine:

```
ssh 127.0.0.1 2222

```
install the python Prerequisites provided
in order to run the script

```
sudo ./config.sh
```
at last run the script:

```
python index.py

```

## Set up a Google Plus auth application.

    go to https://console.developers.google.com/project and login with Google.
    Create a new project
    Name the project
    Select "API's and Auth-> Credentials-> Create a new OAuth client ID" from the project menu
    Select Web Application
    On the consent screen, type in a product name and save.
    In Authorized javascript origins add: http://0.0.0.0:8080 http://localhost:8080
    Click create client ID
    Click download JSON and save it into the root director of this project.
    Rename the JSON file "client_secret.json"
    In main.html replace the line "data-clientid="15454545427894-jmhfsdicfbufdss3je650vepp455555.apps.googleusercontent.com" so that it uses your Client ID from the web applciation.


## Authors

*Deya nemo *
## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

