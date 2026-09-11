"""Measuring the extraction stage the way section 5.2 of the paper does.

`calibrate.py` sweeps the alignment threshold over a gold set and reports
precision, recall and F1 at every step -- the number that replaces the paper's
borrowed 0.9. `gold/` holds the hand-labelled documents it runs on.
"""
