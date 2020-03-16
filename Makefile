# DERIVED FROM CIS 322
# Distributed initially by Professor Michal Young in Fall 2017
# Gnu make and bash are required. 
#
# To run from source: 
#    make install
#    make run 
# 


# Many recipes need to be run in the virtual environment, 
# so run them as $(INVENV) command
INVENV = . env/bin/activate ;


##
##  Virtual environment
##     
PYVENV = python3 -m venv
env:
	$(PYVENV)  env
	($(INVENV) pip install -r requirements.txt )

install:  env  credentials

# 'make run' runs the built-in Flask server.  Useful for debugging,
# but not suitable for long-running service.
#
credentials:  backend/credentials.ini
backend/credentials.ini:
	echo "You just install the database and credentials.ini for it"

run:	env credentials
	$(INVENV) cd backend; python3 keysafe_api.py



##
## Preserve virtual environment for git repository
## to duplicate it on other targets
##
dist:	env
	$(INVENV) pip freeze >requirements.txt


# 'clean' and 'veryclean' are typically used before checking 
# things into git.  'clean' should leave the project ready to 
# run, while 'veryclean' may leave project in a state that 
# requires re-running installation and configuration steps
# 
clean:
	cd backend; rm -f *.pyc
	cd backend; rm -rf __pycache__

veryclean:
	make clean
	rm -rf env