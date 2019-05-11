GIT_MSG=""

tsc
git add .
git status

if [ -z "$GIT_MSG" ]
then
  echo "REMINDER! Have you updated the exports in index.ts??"
  echo "Git commit message:"
  read GIT_MSG
fi

if [ -z "$GIT_MSG" ]
then
  echo "No message, exiting..."
  exit
fi

git commit -m "$GIT_MSG"
git push