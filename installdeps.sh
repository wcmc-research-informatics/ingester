# Check whether we're inside a virtualenv.
# (See https://stackoverflow.com/a/13864829)
if [ -z "${VIRTUAL_ENV+x}" ]; then
  echo "need to be inside a virtualenv"
  exit 1
else 
  echo "virtualenv folder is: $VIRTUAL_ENV"
fi
pip install -r requirements.txt --upgrade --upgrade-strategy eager

