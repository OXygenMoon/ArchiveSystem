sudo systemctl daemon-reload
sudo systemctl restart redis
sudo systemctl restart archive
sudo systemctl restart nginx
sudo systemctl status archive          # 检查状态
