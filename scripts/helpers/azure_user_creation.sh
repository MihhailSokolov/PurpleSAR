#! /bin/bash

Help() {
    echo "Script to automatically create SAR users with the required RBAC rights in the specified resource group."
    echo
    echo "Syntax: azure_user_creation.sh [-h|-t|-n|-p|-s|-r]"
    echo "Options:"
    echo "-h Show this help"
    echo "-t Team number or name (mandatory)"
    echo "-n Number of team members (defaults to 1 if not set)"
    echo "-p Password for the user (mandatory)"
    echo "-s Subscription ID (mandatory)"
    echo "-r Resource Group name (mandatory)"
    exit 1
}

# Init variables
OPTIND=1
unset -v team_name
unset -v password
unset -v subscription_id
unset -v resource_group
member_number=1

# Parse options
while getopts "h?t:n:p:s:r:" opt; do
    case $opt in
        h) Help ;;
        t) team_name=$OPTARG
           ;;
        n) member_number=$OPTARG
           ;;
        p) password=$OPTARG
           ;;
        s) subscription_id=$OPTARG
           ;;
        r) resource_group=$OPTARG
           ;;
    esac
done

shift "$(( OPTIND - 1 ))"

# Error in case one of the mandatory options is empty
if [ -z "$team_name" ] || [ -z "$password" ] || [ -z "$subscription_id" ] || [ -z "$resource_group" ]; then
    echo "Missing -t, -p, -s or -r" >&2
    exit 1
fi

echo "Variables: team_name: $team_name, member_number: $member_number, password: $password, subscription_id: $subscription_id, resource_group: $resource_group"

current_member=1

until [ $current_member -ge $((member_number + 1)) ]; do
    # Concat user display name & user principal name
    user_display_name="Team ${team_name} - Participant ${current_member}"
    upn="team${team_name}_participant${current_member}@hexaplex.ch"
    # Create Azure user for current member
    echo "Creating Entra ID user for ${upn}"
    az ad user create --display-name "${user_display_name}" --password $password --user-principal-name $upn
    # Assign RBAC access to specified resource group
    echo "Assigning RBAC access (Reader) to specified resource group for user ${upn}"
    az role assignment create --assignee "${upn}" --role "Reader" --scope "/subscriptions/${subscription_id}/resourcegroups/${resource_group}"
    ((current_member++))
done