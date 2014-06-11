#include <Python.h>
#include <stoken.h>
 
static PyObject *StokenError;

static PyObject*
get_code(PyObject* self, PyObject* args, PyObject *keywds)
{
	struct stoken_ctx *ctx = stoken_new();
	char* token = "252503079680743142131101346153112272336172670304467711744173124152503452716757206";
	char* deviceid = "123";
	char* password = "test";
	char* pin = "6666";
	char out[STOKEN_MAX_TOKENCODE + 1];
	int rc;
 
	static char *kwlist[] = {"token", "deviceid", "password", "pin", NULL};
	if (!PyArg_ParseTupleAndKeywords(args, keywds, "|ssss", kwlist, &token, &deviceid, &password, &pin))
		return NULL;

	rc = stoken_import_string(ctx, token);
	if (rc)
	{
		char *res;
		sprintf(res, "stoken_import_string returned %d\n", rc);
		PyErr_SetString(StokenError, res);
	}

	rc = stoken_decrypt_seed(ctx, password, deviceid);
	if (rc)
	{
		char *res;
		sprintf(res, "stoken_decrypt_send returned %d\n", rc);
		PyErr_SetString(StokenError, res);
	}

	rc = stoken_compute_tokencode(ctx, time(NULL), pin, out);
	if (rc)
	{
		char *res;
		sprintf(res, "stoken_compute_tokencode returned %d\n", rc);
		PyErr_SetString(StokenError, res);
	}

	return Py_BuildValue("s", out);
}
 
static PyMethodDef StokenMethods[] =
{
	 {"get_code", (PyCFunction)get_code, METH_VARARGS | METH_KEYWORDS, "Generate a new RSA token. **kwargs specifies configuration, otherwise default test values are used"},
	 {NULL, NULL, 0, NULL}
};
 
PyMODINIT_FUNC
initstoken(void)
{
	PyObject *m;

	m = Py_InitModule("stoken", StokenMethods);
	if (m == NULL)
		return;

	StokenError = PyErr_NewException("stoken.error", NULL, NULL);
	Py_INCREF(StokenError);
	PyModule_AddObject(m, "error", StokenError);
}
