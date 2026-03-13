#!/bin/bash

# Check if the current repository has internal remote configured
if git remote get-url internal &>/dev/null; then
    echo "Internal remote repository found."
else
    echo "Internal remote repository not found. Please enter the internal remote repository URL:"
    read -p "Enter internal remote repository URL: " internal_repo_url
    # Add internal remote repository
    git remote add internal "$internal_repo_url"
    echo "Internal remote repository added: $internal_repo_url"
fi

# Display operation menu
echo "Please choose an operation:"
echo "1. Pull code from GitHub repository"
echo "2. Pull code from internal repository"
echo "3. Push code to GitHub repository"
echo "4. Push code to internal repository"
echo "5. Push code to both GitHub and internal repositories"

read -p "Enter option [1-5]: " option

# Get the branch name
read -p "Enter branch name: " branch_name

# Execute corresponding action based on user's choice
case "$option" in
    1)
        # Pull code from GitHub repository
        echo "Pulling code from GitHub repository, branch: $branch_name"
        git pull origin "$branch_name"
        ;;
    2)
        # Pull code from internal repository
        echo "Pulling code from internal repository, branch: $branch_name"
        git pull internal "$branch_name"
        ;;
    3)
        # Push code to GitHub repository
        echo "Pushing code to GitHub repository, branch: $branch_name"
        git push origin "$branch_name"
        ;;
    4)
        # Push code to internal repository
        echo "Pushing code to internal repository, branch: $branch_name"
        git push internal "$branch_name"
        ;;
    5)
        # Push code to both GitHub and internal repositories
        echo "Pushing code to both GitHub and internal repositories, branch: $branch_name"
        git push origin "$branch_name" && git push internal "$branch_name"
        ;;
    *)
        # Handle invalid option
        echo "Invalid option, please enter a number between 1 and 5."
        exit 1
        ;;
esac

echo "Operation completed."
