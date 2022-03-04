#!/bin/bash

if systemctl --quiet is-active wg-quick@wg0.service
then
  echo "Reloading wg0 config..."
  wg syncconf wg0 <(wg-quick strip wg0)
else
  echo "Restarting wg0 service..."
  systemctl restart wg-quick@wg0.service
fi
