"""
This module exposes an api to deal with db operations on no-sql databases.
Currently couchdb support is included.
"""

import couchdb

COUCHDB = 'couchdb'
LOCALHOST = 'localhost'


def todict(conn_string, kwargs):
    """Converts the input connection string into a dictionary.

    Assumption: Connection string is of the format
    'driver=couchdb;server=localhost;uid=database_uid;pwd=database_pwd'
    """
    ret = {}
    conn_dict = {}
    for c_str in conn_string:
        arr = c_str.split(';')
        for elem in arr:
            temp = elem.split('=')
            ret[temp[0]] = temp[1]

    conn_dict = ret.copy()
    conn_dict.update(kwargs)
    return conn_dict


class NsOdbc(object):
    """An abstraction layer to make api calls to a non relational database.

    Currently the API provided is:
    connect
    create
    get_doc
    insert_update_doc
    delete_doc
    """

    def __init__(self):
        self.version = '1.1'
        self.conn = None

    def connect(self, *conn_string, **kwargs):
        """Returns a connection object required for further operations
        Input: connection string or connection parameters
        Returns: connection object
        """
        conn_dict = {}
        conn_dict = todict(conn_string, kwargs)

        # couchdb specific block.
        if conn_dict['driver'] == COUCHDB:
            auth_pair = (conn_dict['uid'], conn_dict['pwd'])
            if conn_dict['server'] == LOCALHOST:
                cnxn = ConnectionCouch(couchdb.Server(), auth_pair)
            else:
                server_pair = "http://{0}:{1}/".format(
                    conn_dict['server'], conn_dict['port'])
                cnxn = ConnectionCouch(couchdb.Server(server_pair), auth_pair)
            self.conn = cnxn
            return cnxn

    def get_attributes(self):
        """Returns API version"""
        return self.version


class ConnectionCouch(object):
    """Connection class.

    This class is specific to couchdb operations.
    For others a new class will be needed (following same standards)
    """

    def __init__(self, conn, credentials):
        self.conn = conn
        self.conn.resource.credentials = credentials
        self.database = {}

    def create(self, db_name):
        """Create a database.
        If the database exists, return the same and send a True flag.
        This way, a connection object will only be created once.
        """
        try:
            self.database[db_name] = DatabaseCouch(self.conn.create(db_name))
            return self.database[db_name], False
        except couchdb.http.PreconditionFailed:
            self.database[db_name] = DatabaseCouch(self.conn[db_name])
            return self.database[db_name], True

    def connected_databases(self):
        """
        Return the connected databases of this connection
        """
        return self.database

    def delete(self, db_name):
        """
        Delete database specified in the parameter
        """
        self.conn.delete(db_name)


class DatabaseCouch(object):
    """Database specific class exposing the API.
    """

    def __init__(self, database):
        self.database = database

    def insert_update_doc(self, doc, update_key=''):
        """Insert or update a document
        For updating, a key has to be provided against
        which a document will be updated
        """
        try:
            doc_id, _ = self.database.save(doc)
            return doc_id
        except couchdb.http.ResourceConflict:
            l_doc = self.database.get(doc['_id'])
            l_doc[update_key] = doc[update_key]
            doc_id, _ = self.database.save(l_doc)
            return doc_id

    def get_docs(self, view_url, key):
        """Select docs

        A view url is used as select query with the key as a where condition
        """
        view_results = self.database.view(view_url, key=key)
        return view_results.rows

    def delete_doc(self, doc_id):
        """
        Delete document based on the doc id
        """
        doc = self.database.get(doc_id)
        self.database.delete(doc)

    def create_view(self, design, views):
        """
        This is a couchdb functionality. Helps in creating views needed
        for querying the database.
        Input: Design name, view definition
        """
        doc = {}
        doc["_id"] = "_design/" + design
        doc["language"] = "javascript"
        doc["views"] = views
        self.database.save(doc)


def nsodbc_factory():
    """factory method to consume the API"""
    return NsOdbc()


def init_flow_db(flow_database):
    """
    Initialize/Refresh flow database
    Args:
        flow_database
    """
    views = {}
    views["flow"] = {}
    views["flow"]["map"] = "function(doc) " + \
                           "{\n  emit(doc._id, doc);\n}"
    views["match"] = {}
    views["match"]["map"] = "function(doc) " + \
                            "{\nif(doc.data.OFPFlowStats.match)" + \
                            "{\n  emit(" + \
                            "[doc.data.OFPFlowStats.table_id, " + \
                            "doc.data.OFPFlowStats.match], " + \
                            "doc );\n}\n}"
    flow_database.create_view("flows", views)


def init_switch_db(switch_database):
    """
    Initialize/refresh switch database
    Args:
        switch_database
    """
    views = {}
    views["switch"] = {}
    views["switch"]["map"] = "function(doc) " + \
                             "{\n  emit(doc._id, doc);\n}"
    switch_database.create_view("switches", views)
