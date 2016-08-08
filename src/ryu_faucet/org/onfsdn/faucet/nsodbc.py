"""
This module exposes an api to deal with db operations on no-sql databases.
Currently couchdb support is included.
"""
COUCHDB = 'couchdb'
LOCALHOST = 'localhost'

try:
    import couchdb
except ImportError, error:
    raise error


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
            if conn_dict['server'] == LOCALHOST:
                cnxn = ConnectionCouch(couchdb.Server(),
                                       (conn_dict['uid'], conn_dict['pwd']))
            else:
                cnxn = ConnectionCouch(couchdb.Server(
                    "http://{0}:{1}/".format(conn_dict['server'],
                                             conn_dict['port'])),
                    (conn_dict['uid'], conn_dict['pwd']))
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
        If the databse exists, return the same and send a True flag.
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
