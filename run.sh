sudo systemctl daemon-reload
sudo systemctl restart redis
sudo systemctl restart myapp
sudo systemctl restart nginx
sudo systemctl status myapp          # 检查状态
