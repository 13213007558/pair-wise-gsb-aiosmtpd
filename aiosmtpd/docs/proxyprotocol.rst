.. _ProxyProtocol:

========================
 PROXY Protocol Support
========================

When put behind a "proxy" / load balancer,
server programs can no longer "see" the original client's actual IP Address and Port.

This also affects ``aiosmtpd``.

The |HAProxyDevelopers|_ have created a protocol called "PROXY Protocol"
designed to solve this issue.
You can read the reasoning behind this in `their blog`_.

.. _`HAProxyDevelopers`: https://www.haproxy.com/company/about-us/
.. |HAProxyDevelopers| replace:: **HAProxy Developers**
.. _their blog: https://www.haproxy.com/blog/haproxy/proxy-protocol/

This initiative has been accepted and supported by many important software and services
such as `Amazon Web Services`_, `HAProxy`_, `NGINX`_, `stunnel`_, `Varnish`_, and many others.

.. _Amazon Web Services: https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-proxy-protocol.html
.. _HAProxy: http://cbonte.github.io/haproxy-dconv/2.3/configuration.html#5.2-send-proxy
.. _NGINX: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html#proxy_protocol
.. _stunnel: https://www.stunnel.org/static/stunnel.html#proxy
.. _Varnish: https://info.varnish-software.com/blog/proxy-protocol-original-value-client-identity

``aiosmtpd`` implements the PROXY Protocol as defined in the documentation accompanying |HAProxy2.3.0|_;
*both* Version 1 and Version 2 are supported.

.. _HAProxy2.3.0: https://github.com/haproxy/haproxy/blob/v2.3.0/doc/proxy-protocol.txt
.. |HAProxy2.3.0| replace:: **HAProxy v2.3.0**


Activating
==========

To activate ``aiosmtpd``'s PROXY Protocol Support,
you have to set the :attr:`~aiosmtpd.smtp.SMTP.proxy_protocol_timeout` parameter of the SMTP Class
to a positive numeric value (``int`` or ``float``)

The `PROXY Protocol documentation suggests`_ that the timeout should not be less than 3.0 seconds.

.. _PROXY Protocol documentation suggests: https://github.com/haproxy/haproxy/blob/v2.3.0/doc/proxy-protocol.txt#L172-L174

.. important::

   Once you activate PROXY Protocol support,
   standard (E)SMTP handshake is **no longer available**.

   Clients trying to connect to ``aiosmtpd`` will be REQUIRED
   to send the PROXY Protocol Header
   before they can continue with (E)SMTP transaction.

   This is `as specified`_ in the PROXY Protocol documentation.

.. _as specified: https://github.com/haproxy/haproxy/blob/v2.3.0/doc/proxy-protocol.txt#L176-L180


``handle_PROXY`` Hook
=====================

In addition to activating the PROXY protocol support as described above,
you MUST implement the ``handle_PROXY`` hook.
If the :attr:`~aiosmtpd.smtp.SMTP.handler` object does not implement ``handle_PROXY``,
then all connection attempts will be rejected.

The signature of ``handle_PROXY`` must be as follows:

.. method:: handle_PROXY(server, session, envelope, proxy_data)

   :param server: The :class:`~aiosmtpd.smtp.SMTP` instance invoking the hook.
   :type server: aiosmtpd.smtp.SMTP
   :param session: The Session data *so far* (see Important note below)
   :type session: Session
   :param envelope: The Envelope data *so far* (see Important note below)
   :type envelope: Envelope
   :param proxy_data: The result of parsing the PROXY Header
   :type proxy_data: ProxyData
   :return: Truthy or Falsey, indicating if the connection may continue or not, respectively

   .. important::

      The ``session.peer`` attribute will contain the ``IP:port`` information
      of the **directly adjacent** client.
      In other word,
      it will contain the endpoint identifier of the proxying entity.

      Endpoint identifier of the "original" client will be recorded
      *only* in the :paramref:`handle_PROXY.proxy_data` parameter

      The ``envelope`` data will usually be empty(ish),
      because the PROXY handshake will take place before
      client can send any transaction data.


Parsing the Header
==================

You do not have to concern yourself with parsing the PROXY Protocol header;
the ``aiosmtpd.proxy_protocol`` module contains the full parsing logic.

All you need to do is to *validate* the parsed result in the ``handle_PROXY`` hook.

.. py:module:: aiosmtpd.proxy_protocol

Enums
=====

.. class:: AF

   .. py:attribute:: UNSPEC
      :value: 0

   .. py:attribute:: INET
      :value: 1

   .. py:attribute:: INET6
      :value: 2

   .. py:attribute:: UNIX
      :value: 3

   For Version 1, ``UNKNOWN`` is mapped to ``UNSPEC``.

.. class:: PROTO

   .. py:attribute:: UNSPEC
      :value: 0
   .. py:attribute:: STREAM
      :value: 1
   .. py:attribute:: DGRAM
      :value: 2

   For Version 1, ``UNKNOWN`` is mapped to ``UNSPEC``, and ``TCP`` is mapped into ``STREAM``

.. class:: V2_CMD

   .. py:attribute:: LOCAL
      :value: 0
   .. py:attribute:: PROXY
      :value: 1


``ProxyData`` API
=================

.. py:class:: ProxyData(\
   version=None\
   )

   |
   | :part:`Attributes & Properties`

   .. py:attribute:: version
      :type: Optional[int]

      Contains the version of the PROXY Protocol header.

      If ``None``, it indicates that parsing has failed and the header is malformed.

   .. py:attribute:: command
      :type: V2_CMD

      Contains the `command`_. Only set if ``version=2``

   .. py:attribute:: family
      :type: AF

      Contains the `address family`_.

      Valid values for Version 1 excludes :attr:`AF.UNIX`.

   .. py:attribute:: protocol
      :type: PROTO

      Contains an integer indicating the `transport protocol being proxied`_.

      Valid values for Version 1 excludes :attr:`PROTO.DGRAM`.

   .. py:attribute:: src_addr
      :type: Union[~ipaddress.IPv4Address, ~ipaddress.IPv6Address, ~typing.AnyStr]

      Contains the source address
      (i.e., address of the "original" client).

      The type of this attribute depends on the :attr:`address family <family>`.

   .. py:attribute:: dst_addr
      :type: Union[~ipaddress.IPv4Address, ~ipaddress.IPv6Address, ~typing.AnyStr]

      Contains the destination address
      (i.e., address of the proxying entity to which the "original" client connected).

      The type of this attribute depends on the address family.

   .. py:attribute:: src_port
      :type: int

      Contains the source port
      (i.e., port of the "original" client).

      Valid only for address family of :attr:`AF.INET` or :attr:`AF.INET6`

   .. py:attribute:: dst_port
      :type: int

      Contains the destination port
      (i.e., port of the proxying entity to which the "original" client connected).

      Valid only for address family of :attr:`AF.INET` or :attr:`AF.INET6`

   .. py:attribute:: rest
      :type: ByteString

      The contents depend on the version of the PROXY header *and* (for version 2)
      the address family.

      For PROXY Header version 1,
      it contains all the bytes following ``b"UNKNOWN"`` up until, but not including,
      the ``CRLF`` terminator.

      For PROXY Header version 2:

        * For address family ``UNSPEC``,
          it contains all the bytes following the 16-octet header preamble
        * For address families :attr:`AF.INET`, :attr:`AF.INET6`, and :attr:`AF.UNIX`
          it contains all the bytes following the address information

   .. py:attribute:: tlv
      :type: aiosmtpd.proxy_protocol.ProxyTLV

      This property contains the result of the TLV Parsing attempt of the :attr:`rest` attribute.

      If this property returns ``None`` that means either
      (1) :attr:`rest` is empty, or
      (2) TLV Parsing is not successful.

   .. py:attribute:: valid
      :type: bool

      This property will indicate if PROXY Header is valid or not.

   .. py:attribute:: whole_raw
      :type: bytearray

      This attribute contains the whole, undecoded and unmodified, PROXY Header.
      For version 1, it contains everything up to and including the terminating ``\r\n``.
      For version 2, it contains everything up to and including the last TLV Vector.

      If you need to verify the ``CRC32C`` TLV Vector (PROXYv2),
      you should run the CRC32C calculation against the contents of this attribute.
      For more information, see the next section, :ref:`crc32c`.

   .. py:attribute:: tlv_start
      :type: int

      This attribute points to the first TLV Vector *if exists*.

      If you need to verify the ``CRC32C`` TLV Vector,
      you should run the CRC32C calculation against the contents of this attribute.

      The value will be ``None`` if PROXY version is 1.

   .. py:attribute:: error
      :type: str

      If not an empty string, contains the error encountered when parsing
      the PROXY Protocol header.

   .. py:attribute:: checksum_status
      :type: CRC32CStatus

      The outcome of the PROXYv2 ``CRC32C`` TLV Vector verification, kept
      distinct from :attr:`error` so that "not provided", "verified" and
      "verification failed" are all distinguishable. See :ref:`crc32c`.

      Defaults to :attr:`CRC32CStatus.NOT_PROVIDED`; an absent checksum is
      never reported as :attr:`CRC32CStatus.VALID`.

   |
   | :part:`Methods`

   .. py:method:: with_error(error_msg: str) -> ProxyData

      :param str error_msg: Error message
      :return: self

      Sets the instance's :attr:`error` attribute and returns itself.

   .. py:method:: same_attribs(_raises=False, **kwargs) -> bool

      :param _raises: If ``True``, raise exception if attribute not match/not found,
         instead of returning a bool. Defaults to ``False``
      :type _raises: bool
      :raises ValueError: if ``_raises=True`` and attribute is found but value is wrong
      :raises KeyError: if ``_raises=True`` and attribute is not found

      A helper method to quickly verify whether an attribute exists
      and contain the same value as expected.

      Example usage::

         proxy_data.same_attribs(
             version=1,
             protocol=b"TCP4",
             unknown_attrib=None
         )

      In the above example,
      ``same_attribs`` will check that all attributes
      ``version``, ``protocol``, and ``unknown_attrib`` exist,
      and contains the values ``1``, ``b"TCP4"``, and ``None``, respectively.

      Missing attributes and/or differing values will return a ``False``
      (unless ``_raises=True``)

      .. note::

         For other examples, take a look inside the ``test_proxyprotocol.py`` file.
         That file *extensively* uses ``same_attribs``.

   .. py:method:: __bool__()

      Allows an instance of ``ProxyData`` to be evaluated as boolean.
      In actuality, it simply returns the :attr:`valid` property.


``ProxyTLV`` API
================

.. py:class:: ProxyTLV()

   This class parses the `TLV portion`_ of the PROXY Header
   and presents the value in an easy-to-use way:
   A "TLV Vector" whose "Type" is found in :attr:`PP2_TYPENAME`
   can be accessed through the `.<NAME>` attribute.

   It is a subclass of :class:`dict`,
   so all of ``dict``'s methods are available.
   It is basically a `Dict[str, Any]` with additional methods and attributes.
   The list below only describes methods & attributes added to this class.

   .. py:attribute:: PP2_TYPENAME
      :type: Dict[int, str]

      A mapping of numeric Type to a human-friendly Name.

      The names are identical to the ones `listed in the documentation`_,
      but with the ``PP2_TYPE_``/``PP2_SUBTYPE_`` prefixes removed.

      .. note::

         The ``SSL`` Name is special.
         Rather than containing the TLV Subvectors as described in the standard,
         it is a ``bool`` value that indicates whether the PP2_SUBTYPE_SSL

   .. py:attribute:: tlv_loc
      :type: Dict[str, int]

      A mapping to show the start location of certain TLV Vectors.

      The keys are the TYPENAME (see :attr:`PP2_TYPENAME` above),
      and the value is the offset from start of the TLV Vectors.

   .. py:method:: same_attribs(_raises=False, **kwargs) -> bool

      :param _raises: If ``True``, raise exception if attribute not match/not found,
         instead of returning a bool. Defaults to ``False``
      :type _raises: bool
      :raises ValueError: if ``_raises=True`` and attribute is found but value is wrong
      :raises KeyError: if ``_raises=True`` and attribute is not found

      A helper method to quickly verify whether an attribute exists
      and contain the same value as expected.

      Example usage::

         assert isinstance(proxy_tlv, ProxyTLV)
         proxy_tlv.same_attribs(
             AUTHORITY=b"some_authority",
             SSL=True,
         )

      In the above example,
      ``same_attribs`` will check that the attributes
      ``AUTHORITY`` and ``SSL`` exist,
      and contains the values ``b"some_authority"`` and ``True``, respectively.

      Missing attributes and/or differing values will return a ``False``
      (unless ``_raises=True``)

      .. note::

         For other examples, take a look inside the ``test_proxyprotocol.py`` file.
         That file *extensively* uses ``same_attribs``.

   .. py:classmethod:: from_raw(raw) -> Optional[ProxyTLV]

      :param raw: The raw bytes containing the TLV Vectors
      :type raw: ByteString
      :return: A new instance of ProxyTLV, or ``None`` if parsing failed

      This triggers the parsing of raw bytes/bytearray into a ProxyTLV instance.

      Internally it relies on the :meth:`parse` classmethod to perform the parsing.

      Unlike the default behavior of :meth:`parse`,
      ``from_raw`` will NOT perform a partial parsing.

   .. py:classmethod:: parse(chunk, partial_ok=True) -> Dict[str, Any]

      :param chunk: The bytes to parse into TLV Vectors
      :type chunk: ByteString
      :param partial_ok: If ``True``, return partially-parsed TLV Vectors as is.
         If ``False``, (re)raise ``MalformedTLV``
      :type partial_ok: bool
      :return: A mapping of typenames and values

      This performs a recursive parsing of the bytes.
      If it encounters a TYPE that ProxyTLV doesn't recognize,
      the TLV Vector will be assigned a typename of `"xNN"`

      Partial parsing is possible when ``partial_ok=True``;
      if during the parsing an error happened,
      `parse` will abort returning the TLV Vectors it had successfully decoded.

   .. py:classmethod:: name_to_num(name) -> Optional[int]

      :param name: The name to back-map into TYPE numeric
      :type name: str
      :return: The numeric value associated to the typename, ``None`` if no such mapping is found

      This is a helper method to perform back-mapping of typenames.

.. _crc32c:

CRC32C Checksum Verification
============================

The PROXYv2 specification defines an optional ``CRC32C`` TLV Vector
(``PP2_TYPE_CRC32C = 0x03``) carrying a Castagnoli CRC32C checksum computed
over the whole PROXY header, with the 4-octet checksum field itself zeroed out
during calculation.

``aiosmtpd`` ships a dependency-free, pure-Python CRC32C implementation
(:func:`crc32c`) and can verify this TLV Vector automatically, according to a
configurable policy. No third-party or binary package is required.

.. important::

   A CRC32C checksum can only detect **transport corruption** of the PROXY
   header. It is *not* an authentication mechanism and provides no integrity
   guarantee against a sender who can recompute the checksum.

   Trust in the proxy itself must still be established independently through
   your deployment/ingress configuration (for example, only accepting
   connections from the proxy's addresses or a private network). In
   particular, the presence of an ``SSL`` TLV Vector — even a checksum-valid
   one — must never be interpreted as proof that the end user has
   authenticated; those flags only describe the transport up to the proxy.

.. class:: CRC32CPolicy

   Selects how strictly the PROXYv2 ``CRC32C`` TLV Vector is verified.
   Pass one of its members as the
   :attr:`~aiosmtpd.smtp.SMTP.proxy_protocol_checksum_policy` parameter, or to
   :func:`get_proxy` directly. The policy has no effect on PROXYv1 headers.

   .. py:attribute:: IGNORE
      :value: 0

      The default. Verification is never attempted and
      :attr:`ProxyData.checksum_status` stays
      :attr:`CRC32CStatus.NOT_PROVIDED`. The checksum TLV, if present, is still
      parsed and exposed like any other TLV Vector.

   .. py:attribute:: OPTIONAL
      :value: 1

      If a ``CRC32C`` TLV Vector is present it is verified; a missing one is
      accepted. A missing checksum is reported as
      :attr:`CRC32CStatus.NOT_PROVIDED` — it is **never** reported as
      :attr:`CRC32CStatus.VALID`. A present-but-wrong or malformed checksum
      invalidates the header.

   .. py:attribute:: REQUIRED
      :value: 2

      A present, correctly-sized and matching ``CRC32C`` TLV Vector is
      mandatory. A missing, malformed or mismatching checksum invalidates the
      header.

.. class:: CRC32CStatus

   The outcome of looking for and verifying the ``CRC32C`` TLV Vector. This is
   deliberately separate from :attr:`ProxyData.error`: a header can parse
   perfectly while its checksum is absent or wrong.

   .. py:attribute:: NOT_PROVIDED
      :value: 0

      No verification was attempted (:attr:`CRC32CPolicy.IGNORE`, or a PROXYv1
      header) or no ``CRC32C`` TLV Vector was present.

   .. py:attribute:: VALID
      :value: 1

      A ``CRC32C`` TLV Vector was present and the recomputed checksum matched.

   .. py:attribute:: INVALID
      :value: 2

      A ``CRC32C`` TLV Vector was present but unusable or mismatching — for
      example a checksum mismatch, a duplicate ``CRC32C`` TLV Vector, a value
      whose length is not exactly 4 octets, a TLV Vector whose declared length
      runs past the end of the header, or a truncated TLV Vector.

Verification details
--------------------

Only **top-level** TLV Vectors are walked when locating the checksum, so the
offsets of subvectors nested inside an ``SSL`` TLV Vector never influence the
checksum range: the checksum is always calculated over the whole header with
only the 4-octet ``CRC32C`` value zeroed. :attr:`ProxyData.whole_raw` is never
mutated; verification operates on a zeroed copy.

SMTP bytes that arrive in the same TCP segment as the PROXY header are not part
of the header and are never consumed by the preamble parser; they remain in the
stream reader for the SMTP state machine.

Under :attr:`CRC32CPolicy.REQUIRED` (and for any malformed/mismatching
checksum under :attr:`CRC32CPolicy.OPTIONAL`), the failed preamble makes
:attr:`ProxyData.valid` false. The SMTP connection is then rejected *before*
the ``220`` greeting and before the ``handle_PROXY`` hook is invoked, so a
failing preamble can never reach the SMTP command handler.

.. function:: crc32c(data) -> int

   :param data: The bytes (``bytes``, ``bytearray`` or ``memoryview``) to
      calculate the checksum over
   :return: The CRC32C (Castagnoli) checksum as an unsigned 32-bit integer

   Pure-Python, table-driven CRC32C with no third-party dependency. The empty
   input yields ``0`` and the ASCII string ``"123456789"`` yields the canonical
   check value ``0xE3069283``.

Manual verification
-------------------

If you prefer to perform verification yourself inside the ``handle_PROXY``
hook instead of selecting a policy, all necessary bytes remain available.
Note the 4-octet value starts *after* the 3-octet type+length header::

    # tlv_loc points at the start (type octet) of the CRC32C TLV Vector;
    # add 3 to skip the "T" and "L" parts and reach the value.
    value_offset = proxy_data.tlv_start + proxy_data.tlv.tlv_loc["CRC32C"] + 3
    checksum_input = bytearray(proxy_data.whole_raw)
    checksum_input[value_offset:value_offset + 4] = b"\x00\x00\x00\x00"
    validated = crc32c(checksum_input).to_bytes(4, "big") == proxy_data.tlv.CRC32C


.. _`command`: https://github.com/haproxy/haproxy/blob/v2.3.0/doc/proxy-protocol.txt#L346-L358
.. _`address family`: https://github.com/haproxy/haproxy/blob/v2.3.0/doc/proxy-protocol.txt#L366-L381
.. _`INET protocol and family`:  https://github.com/haproxy/haproxy/blob/v2.3.0/doc/proxy-protocol.txt#L207-L213
.. _`transport protocol being proxied`: https://github.com/haproxy/haproxy/blob/v2.3.0/doc/proxy-protocol.txt#L388-L402
.. _TLV portion: https://github.com/haproxy/haproxy/blob/v2.3.0/doc/proxy-protocol.txt#L519
.. _listed in the documentation: https://github.com/haproxy/haproxy/blob/v2.3.0/doc/proxy-protocol.txt#L538-L549
.. _PROXYv2 CRC32C validation: https://github.com/haproxy/haproxy/blob/v2.3.0/doc/proxy-protocol.txt#L574-L597
