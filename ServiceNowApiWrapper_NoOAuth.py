#!/.venv-linux/bin/ python
# -*-coding:utf-8 -*-
'''
@File    :   ServiceNowApiWrapper_NoOAuth.py
@Time    :   2024/12/06 13:06:37
@Author  :   Thomas Obarowski 
@Version :   1.0
@Contact :   tjobarow@gmail.com
@License :   MIT License
@Desc    :   Facilitates creating servicenow incident tickets
'''

# Build-in / Generic Imports
import io
import json
import logging

# Import PIP-Installed 3rd party packages
import requests
from requests.auth import HTTPBasicAuth

class ServiceNowError(Exception):
    """A custom exception class that can be raised if an error occurs within
    the ServiceNowCmdbWrapper class.

    Args:
        Exception (str): Implements the 'Exception' base class as it's super
    """
    def __init__(self, message="A ServiceNow related error occurred."):
        self.message = message
        super().__init__(self.message)

class ServiceNowRequestError(ServiceNowError):
    """A custom exception class that can be raised if an API call to ServiceNow
    fails.

    Args:
        ServiceNowError (str): Implements the 'ServiceNowError' base class as it's super
    """
    def __init__(self, message="Error occurred when making an API call to ServiceNow."):
        self.message = message
        super().__init__(self.message)

class ServiceNowAuthenticationError(ServiceNowError):
    """A custom exception class that can be raised if authentication to 
    ServiceNow fails.

    Args:
        ServiceNowError (str): Implements the 'ServiceNowError' base class as it's super
    """
    def __init__(self, message="Error occurred when authenticating to ServiceNow"):
        self.message = message
        super().__init__(self.message)
        
class ServiceNowRequiredFieldError(ServiceNowError):
    """A custom exception class that can be raised if required class fields, 
    such as oAuthClientId are None.

    Args:
        ServiceNowError (str): Implements the 'ServiceNowError' base class as it's super
    """
    def __init__(self, message="There was an error regarding a required field within ServiceNow class"):
        self.message = message
        super().__init__(self.message)

class ServiceNowInvalidCallingFunctionError(ServiceNowError):
    """A custom exception class that can be raised if something tries to call a 
    protected function from outside the class itself.

    Args:
        ServiceNowError (str): Implements the 'ServiceNowError' base class as it's super
    """
    def __init__(self, message="Something called a protected function within ServiceNowCmdbWrapper that cannot be accessed outside of the class instance."):
        self.message = message
        super().__init__(self.message)

class ServiceNowRequiredFieldMissingError(ServiceNowRequiredFieldError):
    """A custom exception class that can be raised if required class fields, 
    such as oAuthClientId are None.

    Args:
        ServiceNowError (str): Implements the 'ServiceNowError' base class as it's super
    """
    def __init__(self, message="One or more required fields are missing."):
        self.message = message
        super().__init__(self.message)
        
class ServiceNowRequiredFieldNullError(ServiceNowRequiredFieldError):
    """A custom exception class that can be raised if required class fields, 
    such as oAuthClientId are None.

    Args:
        ServiceNowError (str): Implements the 'ServiceNowError' base class as it's super
    """
    def __init__(self, message="One or more class fields, which require sa valid value, are None instead."):
        self.message = message
        super().__init__(self.message)

class BasicAuthServiceNowApiClient(requests.Session):
    def __init__(self, service_now_domain: str, username: str, password: str, page_length: int = 1000):
        #Initialize super requests.Session class
        super().__init__()
        
        # Initalize logger and required variables
        self._logger: logging.Logger = logging.getLogger(__name__)
        self._service_now_domain: str = service_now_domain
        self._username: str = username
        self.__password: str = password
        self._page_length = page_length
        self._base_url: str = f"https://{self._service_now_domain}.service-now.com/api/now/v1"
        self._logger.debug(f"Set base URL to {self._base_url}")
        
        # Create basic auth object
        self.auth = HTTPBasicAuth(username=self._username,password=self.__password)
        self._logger.debug("Updated base auth to HTTPBasicAuthentication")
        
        # Update base headers
        self.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "service-now-api-wrapper_v1.0"
        })
        self._logger.debug("Updated base headers")
        self._logger.debug("Finished initalization of BasicAuthServiceNowApiClient")
    
    def get(self, api_endpoint: str, **kwargs):
        self._logger.debug(f"Making get request to {api_endpoint}")
        self._logger.debug(f"Received following kwargs: {json.dumps(kwargs,indent=4)}")
        
        # Set an inital offset to 0
        offset: int = 0
        
        #Add limit parameter to params
        if 'params' in kwargs:
            kwargs['params'].update({'sysparm_limit':self._page_length})
        else:
            kwargs['params'] = {'sysparm_limit':self._page_length}
        
        # Create full url
        full_url: str = self._base_url+api_endpoint
        
        #List to hold data API returns
        returned_data: list[dict] = []
        
        # Have a while loop that will break out of based on condition within loop
        while True:
            self._logger.debug(f"Making request to {full_url}")
            # Send request for data
            response = super().request(method="GET",url=full_url,**kwargs)
            response.raise_for_status()
            self._logger.debug(f"Received successful response from {full_url} with {len(response.json()['result'])} results")
            # Add returned data to list
            returned_data.extend(response.json()['result'])
            self._logger.debug(f"Retrieved {len(returned_data)} records so far from API.")
            # If 'next' exists in the response links, there's a need to paginate
            if 'next' in response.links:
                self._logger.debug("Response from ServiceNow indicates there's another page of data to retreive.")
                self._logger.debug(f"Setting full_url to {response.links['next']['url']}")
                #Update the url to the one provided by 'next'
                full_url = response.links['next']['url']
                # Since the next URL returned by ServiceNow already has our original params
                # We want to remove them from kwargs if they still exist (if this is the
                # first time we are paginating)
                if 'params' in kwargs:
                    self._logger.debug("Removing params in kwargs, as they are already included within next link.")
                    kwargs.pop('params')
                self._logger.debug("Looping to get next page of data")
            # If no 'next' url in response.links, there's no more data to retreive, so break from while
            else:
                self._logger.debug("No 'next' URL was returned by the ServiceNow API, indicating all data has been retrieved. Breaking from request loop.")
                break
            
        return returned_data

class ServiceNowApiWrapper:
    """This class is responsible for interacting with ServiceNow.
    It can create INC records in SN.
    """

    def __init__(
        self,
        service_now_domain: str,
        username: str,
        password: str,
        api_client: BasicAuthServiceNowApiClient
    ):
        """__init__ function of ServiceNowApiWrapper. Sets up service now domain,
        fetches OAuth access token

        Args:
            service_now_domain (str): Name of your SN tenant (i.e mycompany)
            username (str): ServiceNow username
            password (str): ServiceNow username's password
        """
        
        self.__api_client = api_client
        #################################################
        # Initialize protected and private class fields to None

        # Get logger function. If there is a parent logger from the calling function,
        # it will attach as a sub-logger (log as callingClass.ServiceNowCmdbWrapper)
        self._logger = logging.getLogger(__name__)

        self._service_now_domain = None
        self._service_now_base_url = None
        self.__username = None
        self.__password = None

        #################################################
        # Call class field setters (this uses @property/@<variable>.setter)
        # decorator notation to manage the protected/private class fields
        # that are defined above. We want to abstract the priv/prot fields
        # as much as possible
        # Set the servicenow domain, may throw type or value error if improper value provided
        self.service_now_domain = service_now_domain
        # Set credentials
        self.username = username
        self.password = password

    #################################################
    # CLASS FIELD GETTERS/SETTERS
    #################################################
    @property
    def service_now_domain(self) -> str:
        """Returns value of the current ServiceNow Domain

        Returns:
            str: value of service_now_domain
        """
        self._logger.debug(
            f"ServiceNowApiWrapperservice_now_domain getter called. Returning {self._service_now_domain}."
        )
        return self._service_now_domain

    @service_now_domain.setter
    def service_now_domain(self, value: str) -> None:
        """Updates the class to use a new ServiceNow Domain

        Args:
            value (str): new value for ServiceNow Domain

        Raises:
            ValueError: Raised if value of domain provided was None or length 0
            TypeError: Raised if the type provided for domain is not str
            value_error: Raising previous ValueError after logging
            type_error: Raising previous TypeError after logging
        """
        try:
            self._logger.debug(
                f"ServiceNowApiWrapperservice_now_domain setter called with value of {value}."
            )
            if not isinstance(value, str):
                raise TypeError(
                    f"The value provided for ServiceNow domain was not of type str but rather {type(value)}"
                )
            if (value is None) or (len(value) == 0):
                raise ValueError(
                    f"The value provided to ServiceNowApiWrapperservice_now_domain setter was either blank or None."
                )
            self._logger.debug(f"Updated value of self._service_now_domain to {value}")
            self._service_now_domain: str = value
            self.service_now_base_url: str = value
        except TypeError as type_error:
            self._logger.error(type_error)
            raise type_error
        except ValueError as value_error:
            self._logger.error(value_error)
            raise value_error

    @property
    def service_now_base_url(self) -> str:
        """Returns ServiceNow Base URL used in HTTP calls towards the ServiceNow
        Tenant

        Returns:
            str: value of service_now_base_url
        """
        self._logger.debug(
            f"ServiceNowApiWrapperservice_now_base_url getter called. Returning {self._service_now_base_url}."
        )
        return self._service_now_base_url

    @service_now_base_url.setter
    def service_now_base_url(self, value: str) -> None:
        """Updates the current base URL used in HTTP calls to ServiceNow

        Args:
            value (str): value of ServiceNow Domain to insert into the base URL

        Raises:
            ValueError: Raised if provided domain is None or blank str
            value_error: _description_
        """
        try:
            self._logger.debug(
                f"ServiceNowApiWrapperservice_now_base_url setter called with value of {value}."
            )
            if (value is None) or (len(value) == 0):
                raise ValueError(
                    f"The service_now_base_url value provided is either blank or None."
                )
            self._logger.debug(
                f"__setservice_now_base_url function was called with domain value of {value}"
            )
            self._service_now_base_url = f"https://{value}.service-now.com/api/now/v1"
            self._logger.debug(
                f"_service_now_base_url has been updated to {self._service_now_base_url}"
            )
        except ValueError as value_error:
            self._logger.error(value_error)
            raise value_error

    @property
    def username(self) -> str:
        """Returns username used to fetch initial OAuth token from ServiceNow
        Tenant

        Returns:
            str: value of username
        """
        self._logger.debug(
            f"ServiceNowApiWrapperusername getter called. Returning {self.__username}."
        )
        return self.__username

    @username.setter
    def username(self, value: str) -> None:
        """Updates the value of the class's username

        Args:
            value (str): Value of username to use

        Raises:
            ValueError: Raised if value of username provided was None or length 0
            TypeError: Raised if the type provided for username is not str
            value_error: Raising previous ValueError after logging
            type_error: Raising previous TypeError after logging
        """
        try:
            self._logger.debug(
                f"ServiceNowApiWrapperusername setter called with value of {value}."
            )
            if not isinstance(value, str):
                raise TypeError(
                    f"The type provided for username was not of type str but rather {type(value)}"
                )
            if (value is None) or (len(value) == 0):
                raise ValueError(
                    f"The username value provided is either blank or None."
                )

            self._logger.debug(f"Updated value of self.__username to {value}")
            self.__username: str = value
        except TypeError as type_error:
            self._logger.error(type_error)
            raise type_error
        except ValueError as value_error:
            self._logger.error(value_error)
            raise value_error

    @property
    def password(self) -> bool:
        """Returns True/False depending on if the password
        has been defined within the class

        Returns:
            bool: True or False dependent on if password is not None
        """
        self._logger.debug(
            f"ServiceNowApiWrapperpassword getter called. Class will not return the value of password but rather, if it exists: {True if self.__password is not None else False}"
        )
        return True if self.__password is not None else False

    @password.setter
    def password(self, value: str) -> None:
        """Updates the value of the class's password

        Args:
            value (str): Value of password to use

        Raises:
            ValueError: Raised if value of password provided was None or length 0
            TypeError: Raised if the type provided for password is not str
            value_error: Raising previous ValueError after logging
            type_error: Raising previous TypeError after logging
        """
        try:
            self._logger.debug(f"ServiceNowApiWrapperpassword setter called.")
            if not isinstance(value, str):
                raise TypeError(
                    f"The type provided for password was not of type str but rather {type(value)}"
                )
            if (value is None) or (len(value) == 0):
                raise ValueError(
                    f"The password value provided is either blank or None."
                )

            self._logger.debug(f"Updated value of self.__password")
            self.__password: str = value
        except TypeError as type_error:
            self._logger.error(type_error)
            raise type_error
        except ValueError as value_error:
            self._logger.error(value_error)
            raise value_error

    #################################################
    # INCIDENT FUNCTIONS
    #################################################
    def upload_attachment_to_inc(self, sys_id_for_record: str, file: io.StringIO, filename: str):
        """Will upload a io.StringIO file-like object to an incident given the incidents sys_id.

        Args:
            sys_id_for_record (str): ServiceNow sys_id of the incident record to upload the attachment to
            file (io.StringIO): An io.StringIO in-memory file-like object
            filename (str): Name of the file you are uploading - used to set the filename within ServiceNow.

        Raises:
            ServiceNowAuthenticationError: Raised if the ServiceNow API returns an error. - Should be if it returns a 403, but for some reason it isn't - need to update it.
        """
        self._logger.info(f"Uploading file to INC ID {sys_id_for_record}")
        
        servicenow_attachment_url = f"{self._service_now_base_url}/attachment/file"
        # Specify the type for payload
        headers = {
            "Content-Type": "*/*",
            "Accept": "application/json",
        }
        
        params = {
            "table_name":"incident",
            "file_name": filename,
            "table_sys_id": sys_id_for_record
        }
        
        basic_auth_payload = HTTPBasicAuth(self.__username, self.__password)
    
        session = requests.Session()
        request = requests.Request(
            method="POST",
            url=servicenow_attachment_url,
            params=params,
            data=file,
            headers=headers,
            auth=basic_auth_payload,
        )

        prepared_request = session.prepare_request(request=request)

        try:
            self._logger.info(f"Sending API request to ServiceNow to upload file to INC id {sys_id_for_record}.")

            # Make a POST request to the OAuth endpoint
            response = session.send(prepared_request)
            # Raise for status just will throw an exception if the HTTP response code is not in the 2xx family
            response.raise_for_status()
            
            self._logger.info(f"Successfully uploaded attachment to INC sys_id {sys_id_for_record}")
        #TODO Update exception handling to only raise ServiceNowAuthenticationError given a 403 code is returned
        except requests.exceptions.RequestException as req_err:
            self._logger.error(req_err)
            cust_err_msg = f"An error occurring while trying to make API call to upload file to INC id {sys_id_for_record}"
            self._logger.error(cust_err_msg)
            raise ServiceNowAuthenticationError(cust_err_msg)
    
    def get_inc_record(self,inc_num: str|None = None, assigned_user_sys_id: str|None = None, assigned_user_email: str|None = None, opened_by_user_email: str|None = None, max_records_to_return: int = 1) -> list:
        """Returns incidents by incident number, assigned user, or opened by user. This function does not paginate, though.

        Args:
            inc_num (str | None, optional): Number of the incident to return. Defaults to None.
            assigned_user_email (str | None, optional): Email of the assigned user of incidents to return. Defaults to None.
            opened_by_user_email (str | None, optional): Email of the user who opened the incidents to return. Defaults to None.
            max_records_to_return (int, optional): Maximum number of records to return (up to 1,000 - max page size for ServiceNow API). Defaults to 1.

        Raises:
            ServiceNowRequiredFieldMissingError: Raised if the assigned users email did not return a user sys_id from get_sn_user_record(assigned_user_email)
            ServiceNowRequiredFieldMissingError: Raised if the opened by users email did not return a user sys_id from get_sn_user_record(opened_by_user_email)

        Returns:
            list: List of incidents given the provided criteria
        """
        # INFO use prepared request
        session = requests.Session()

        #
        servicenow_inc_url = f"{self._service_now_base_url}/table/incident"
        params = {
            "sysparm_limit": max_records_to_return,
        }
        if inc_num:
            params.update({"sysparm_query":f"number={inc_num}"})
        elif assigned_user_email or assigned_user_sys_id:
            if assigned_user_email and not assigned_user_sys_id:
                try:
                    sys_user_id = self.get_sn_user_record(user_email=assigned_user_email)[0]['sys_id']
                    params.update({"sysparm_query":f"assigned_to={sys_user_id}"})
                except KeyError:
                    raise ServiceNowRequiredFieldMissingError(f"While trying to retrieve incidents assigned to user {assigned_user_email}, ServiceNowApiWrapper was unable to find a user identity in ServiceNow matching that email.")
            elif assigned_user_sys_id and not assigned_user_email:
                params.update({"sysparm_query":f"assigned_to={assigned_user_sys_id}"})
        elif opened_by_user_email:
            try:
                sys_user_id = self.get_sn_user_record(user_email=opened_by_user_email)[0]['sys_id']
                params.update({"sysparm_query":f"opened_by={sys_user_id}"})
            except KeyError:
                raise ServiceNowRequiredFieldMissingError(f"While trying to retrieve incidents opened by user {assigned_user_email}, ServiceNowApiWrapper was unable to find a user identity in ServiceNow matching that email.")

        # Specify the type for payload
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        basic_auth_payload = HTTPBasicAuth(self.__username, self.__password)

        request = requests.Request(
            method="GET",
            url=servicenow_inc_url,
            params=params,
            headers=headers,
            auth=basic_auth_payload,
        )

        prepared_request = session.prepare_request(request=request)

        response = session.send(prepared_request)
        # Raise for status just will throw an exception if the HTTP response code is not in the 2xx family
        response.raise_for_status()

        return response.json()['result']

    def create_incident(
        self,
        short_description: str,
        category: str,
        subcategory: str,
        issue: str,
        assignment_group_id: str,
        full_description: str,
        user_sys_id: str|None = None,
        urgency: str = "3",
        impact: str = "3",
    ) -> str:
        """Creates a new incident record in ServiceNow

        Args:
            short_description (str): String to set the short description to
            category (str): String to set the category to (must already exist within ServiceNow)
            subcategory (str): String to set the subcategory to (must already exist within ServiceNow)
            issue (str): String to set the issue to (must already exist within ServiceNow)
            assignment_group_id (str): ServiceNow sys_id of the group to assign the incident ticket to
            full_description (str): String to set the description to. Can be multi-line string.
            user_sys_id (str | None, optional): ServiceNow sys_id of the user to assign the incident ticket to. Optional. Defaults to None.
            urgency (str, optional): Urgency of incident ticket on a scale of 1-5. Defaults to "3".
            impact (str, optional): Impact of incident ticket on a scale of 1-5. Defaults to "3".

        Raises:
            ServiceNowAuthenticationError: Raised if an error occurs while calling ServiceNow API.

        Returns:
            str: Incident number returned as string
        """
        self._logger.debug(
            "ServiceNowApiWrapper.create_incident function was called."
        )
        self._logger.debug(
            f"Attempting to create new incident record in {self._service_now_domain}."
        )
        # INFO use prepared request
        session = requests.Session()

        #
        servicenow_inc_url = f"{self._service_now_base_url}/table/incident"
        params = {"sysparm_fields": "number,sys_id"}

        # Specify the type for payload
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        basic_auth_payload = HTTPBasicAuth(self.__username, self.__password)

        # INFO construct INC payload
        payload = {
            "short_description": short_description,
            "urgency": urgency,
            "impact": impact,
            "category": category,
            "subcategory": subcategory,
            "u_issue": issue,
            "assignment_group": assignment_group_id,
            "description": full_description,
        }
        
        if user_sys_id is not None:
            payload.update({"assigned_to":user_sys_id})

        request = requests.Request(
            method="POST",
            url=servicenow_inc_url,
            params=params,
            data=json.dumps(payload),
            headers=headers,
            auth=basic_auth_payload,
        )

        prepared_request = session.prepare_request(request=request)

        try:
            self._logger.info("Sending API request to ServiceNow to create incident.")
            self._logger.debug(f"Incident Payload:\n{json.dumps(payload,indent=4)}")
            # Make a POST request to the OAuth endpoint
            response = session.send(prepared_request)
            # Raise for status just will throw an exception if the HTTP response code is not in the 2xx family
            response.raise_for_status()
            self._logger.info(
                f"Successfully create incident {response.json()['result']['number']}"
            )
            return response.json()["result"]
        
        #TODO Update exception handling to only raise ServiceNowAuthenticationError given a 403 code is returned
        except requests.exceptions.RequestException as req_err:
            self._logger.error(req_err)
            cust_err_msg = f"An error occurring while trying to make API call to create INC with following details.\n{json.dumps(payload,indent=4)}"
            self._logger.error(cust_err_msg)
            raise ServiceNowAuthenticationError(cust_err_msg)

    #################################################
    # USER FUNCTIONS
    #################################################
    def get_sn_user_record(self, user_email: str|None = None, custom_query: str|None = None, sys_table: str = "sys_user", sysparm_fields: str = "sys_id,name,user_name,email,title,u_payroll_department_name") -> list:

        api_endpoint = f"/table/{sys_table}"
        
        self._logger.debug(f"Setting sysparm_fields to {sysparm_fields}")
        params = {
            "sysparm_fields": sysparm_fields,
        }
        
        if user_email is not None and custom_query is None:
            self._logger.debug(f"An user_email was specificed but no custom fitler - using query 'email={user_email}'")
            params.update({"sysparm_query": f"email={user_email}"})
        elif user_email is None and custom_query is None:
            self._logger.warning("No user_email or custom_query was provided, meaning API will return max records supported by single page (pagination not yet support but will be in the future)")
        else:
            self._logger.debug(f"A custom_query was specificed, which takes precendence over user_email (if on provided). Using query in request: '{custom_query}'")
            params.update({"sysparm_query": custom_query})
            
        self._logger.debug("Updating sysparm_query to include ORDERBYsys_created_on")
        if 'sysparm_query' in params:
            params['sysparm_query']+="^ORDERBYsys_created_on"
        else:
            params['sysparm_query']="ORDERBYsys_created_on"


        response = self.__api_client.get(api_endpoint=api_endpoint,params=params)
        
        return response
    
        #################################################
    # USER FUNCTIONS
    #################################################
    def get_user_group_memberships(self, user_sys_id: str, max_records_to_return: int = 1, sys_table: str = "sys_user_grmember", sysparm_fields: str = "sys_id,user,group") -> list:
        # INFO use prepared request
        session = requests.Session()

        #
        servicenow_inc_url = f"{self._service_now_base_url}/table/{sys_table}"
        params = {
            "sysparm_query": f"user={user_sys_id}",
            "sysparm_limit": max_records_to_return,
        }

        # Specify the type for payload
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        basic_auth_payload = HTTPBasicAuth(self.__username, self.__password)

        request = requests.Request(
            method="GET",
            url=servicenow_inc_url,
            params=params,
            headers=headers,
            auth=basic_auth_payload,
        )

        prepared_request = session.prepare_request(request=request)

        response = session.send(prepared_request)
        # Raise for status just will throw an exception if the HTTP response code is not in the 2xx family
        response.raise_for_status()

        return response.json()["result"]
    
    
    
    
    
    
    
    
    
    
    