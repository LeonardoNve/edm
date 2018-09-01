#!/bin/sh
sed -i -e "s/<body/<script>alert('INFECTED')<\/script><body/" $1
